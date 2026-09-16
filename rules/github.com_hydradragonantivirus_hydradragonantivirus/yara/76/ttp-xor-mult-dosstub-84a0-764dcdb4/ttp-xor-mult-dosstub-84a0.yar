rule TTP_XOR_MULT_DOSStub_84a0 {
  strings:
    $key_84a0 = { d0 c8 [2] a4 d0 [2] e3 d2 [2] a4 c3 [2] ea cf [2] e6 c5 [2] f1 ce [2] ea 80 [2] d7 }

  condition:
    any of them
}