rule TTP_XOR_MULT_DOSStub_95c8 {
  strings:
    $key_95c8 = { c1 a0 [2] b5 b8 [2] f2 ba [2] b5 ab [2] fb a7 [2] f7 ad [2] e0 a6 [2] fb e8 [2] c6 }

  condition:
    any of them
}