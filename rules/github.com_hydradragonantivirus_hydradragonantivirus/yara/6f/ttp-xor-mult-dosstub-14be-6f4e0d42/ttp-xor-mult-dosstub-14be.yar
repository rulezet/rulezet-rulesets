rule TTP_XOR_MULT_DOSStub_14be {
  strings:
    $key_14be = { 40 d6 [2] 34 ce [2] 73 cc [2] 34 dd [2] 7a d1 [2] 76 db [2] 61 d0 [2] 7a 9e [2] 47 }

  condition:
    any of them
}