rule TTP_XOR_MULT_DOSStub_84b9 {
  strings:
    $key_84b9 = { d0 d1 [2] a4 c9 [2] e3 cb [2] a4 da [2] ea d6 [2] e6 dc [2] f1 d7 [2] ea 99 [2] d7 }

  condition:
    any of them
}