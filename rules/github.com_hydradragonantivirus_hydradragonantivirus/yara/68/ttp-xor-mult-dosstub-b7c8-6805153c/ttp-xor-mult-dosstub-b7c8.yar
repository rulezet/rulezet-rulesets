rule TTP_XOR_MULT_DOSStub_b7c8 {
  strings:
    $key_b7c8 = { e3 a0 [2] 97 b8 [2] d0 ba [2] 97 ab [2] d9 a7 [2] d5 ad [2] c2 a6 [2] d9 e8 [2] e4 }

  condition:
    any of them
}