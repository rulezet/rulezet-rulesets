rule TTP_XOR_MULT_DOSStub_94be {
  strings:
    $key_94be = { c0 d6 [2] b4 ce [2] f3 cc [2] b4 dd [2] fa d1 [2] f6 db [2] e1 d0 [2] fa 9e [2] c7 }

  condition:
    any of them
}