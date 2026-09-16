rule TTP_XOR_MULT_DOSStub_b6c8 {
  strings:
    $key_b6c8 = { e2 a0 [2] 96 b8 [2] d1 ba [2] 96 ab [2] d8 a7 [2] d4 ad [2] c3 a6 [2] d8 e8 [2] e5 }

  condition:
    any of them
}