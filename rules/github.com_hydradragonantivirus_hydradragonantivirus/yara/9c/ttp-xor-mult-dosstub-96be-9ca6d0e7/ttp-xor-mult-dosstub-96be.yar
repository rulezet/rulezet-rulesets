rule TTP_XOR_MULT_DOSStub_96be {
  strings:
    $key_96be = { c2 d6 [2] b6 ce [2] f1 cc [2] b6 dd [2] f8 d1 [2] f4 db [2] e3 d0 [2] f8 9e [2] c5 }

  condition:
    any of them
}