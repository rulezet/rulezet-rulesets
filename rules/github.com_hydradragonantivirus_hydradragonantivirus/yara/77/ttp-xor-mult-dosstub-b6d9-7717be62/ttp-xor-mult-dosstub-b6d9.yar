rule TTP_XOR_MULT_DOSStub_b6d9 {
  strings:
    $key_b6d9 = { e2 b1 [2] 96 a9 [2] d1 ab [2] 96 ba [2] d8 b6 [2] d4 bc [2] c3 b7 [2] d8 f9 [2] e5 }

  condition:
    any of them
}