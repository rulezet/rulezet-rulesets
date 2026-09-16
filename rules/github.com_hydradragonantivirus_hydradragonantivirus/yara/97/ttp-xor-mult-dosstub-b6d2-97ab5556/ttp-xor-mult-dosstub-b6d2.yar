rule TTP_XOR_MULT_DOSStub_b6d2 {
  strings:
    $key_b6d2 = { e2 ba [2] 96 a2 [2] d1 a0 [2] 96 b1 [2] d8 bd [2] d4 b7 [2] c3 bc [2] d8 f2 [2] e5 }

  condition:
    any of them
}