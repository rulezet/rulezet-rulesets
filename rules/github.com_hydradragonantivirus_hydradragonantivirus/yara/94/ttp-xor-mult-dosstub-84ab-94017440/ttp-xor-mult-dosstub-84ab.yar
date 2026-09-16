rule TTP_XOR_MULT_DOSStub_84ab {
  strings:
    $key_84ab = { d0 c3 [2] a4 db [2] e3 d9 [2] a4 c8 [2] ea c4 [2] e6 ce [2] f1 c5 [2] ea 8b [2] d7 }

  condition:
    any of them
}