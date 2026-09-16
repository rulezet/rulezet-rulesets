rule TTP_XOR_MULT_DOSStub_94b4 {
  strings:
    $key_94b4 = { c0 dc [2] b4 c4 [2] f3 c6 [2] b4 d7 [2] fa db [2] f6 d1 [2] e1 da [2] fa 94 [2] c7 }

  condition:
    any of them
}