rule TTP_XOR_MULT_DOSStub_91be {
  strings:
    $key_91be = { c5 d6 [2] b1 ce [2] f6 cc [2] b1 dd [2] ff d1 [2] f3 db [2] e4 d0 [2] ff 9e [2] c2 }

  condition:
    any of them
}