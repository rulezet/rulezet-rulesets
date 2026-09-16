rule TTP_XOR_MULT_DOSStub_86c8 {
  strings:
    $key_86c8 = { d2 a0 [2] a6 b8 [2] e1 ba [2] a6 ab [2] e8 a7 [2] e4 ad [2] f3 a6 [2] e8 e8 [2] d5 }

  condition:
    any of them
}