rule TTP_XOR_MULT_DOSStub_86b4 {
  strings:
    $key_86b4 = { d2 dc [2] a6 c4 [2] e1 c6 [2] a6 d7 [2] e8 db [2] e4 d1 [2] f3 da [2] e8 94 [2] d5 }

  condition:
    any of them
}