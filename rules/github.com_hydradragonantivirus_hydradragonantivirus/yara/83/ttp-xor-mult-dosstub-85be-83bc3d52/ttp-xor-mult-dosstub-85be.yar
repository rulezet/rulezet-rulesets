rule TTP_XOR_MULT_DOSStub_85be {
  strings:
    $key_85be = { d1 d6 [2] a5 ce [2] e2 cc [2] a5 dd [2] eb d1 [2] e7 db [2] f0 d0 [2] eb 9e [2] d6 }

  condition:
    any of them
}