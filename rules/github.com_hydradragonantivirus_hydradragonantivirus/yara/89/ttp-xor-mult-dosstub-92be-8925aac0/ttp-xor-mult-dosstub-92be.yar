rule TTP_XOR_MULT_DOSStub_92be {
  strings:
    $key_92be = { c6 d6 [2] b2 ce [2] f5 cc [2] b2 dd [2] fc d1 [2] f0 db [2] e7 d0 [2] fc 9e [2] c1 }

  condition:
    any of them
}