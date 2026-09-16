rule TTP_XOR_MULT_DOSStub_97c8 {
  strings:
    $key_97c8 = { c3 a0 [2] b7 b8 [2] f0 ba [2] b7 ab [2] f9 a7 [2] f5 ad [2] e2 a6 [2] f9 e8 [2] c4 }

  condition:
    any of them
}