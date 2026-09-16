rule TTP_XOR_MULT_DOSStub_84be {
  strings:
    $key_84be = { d0 d6 [2] a4 ce [2] e3 cc [2] a4 dd [2] ea d1 [2] e6 db [2] f1 d0 [2] ea 9e [2] d7 }

  condition:
    any of them
}