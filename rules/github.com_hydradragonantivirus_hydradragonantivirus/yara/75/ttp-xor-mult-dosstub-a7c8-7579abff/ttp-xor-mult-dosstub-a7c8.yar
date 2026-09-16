rule TTP_XOR_MULT_DOSStub_a7c8 {
  strings:
    $key_a7c8 = { f3 a0 [2] 87 b8 [2] c0 ba [2] 87 ab [2] c9 a7 [2] c5 ad [2] d2 a6 [2] c9 e8 [2] f4 }

  condition:
    any of them
}