rule TTP_XOR_MULT_DOSStub_77be {
  strings:
    $key_77be = { 23 d6 [2] 57 ce [2] 10 cc [2] 57 dd [2] 19 d1 [2] 15 db [2] 02 d0 [2] 19 9e [2] 24 }

  condition:
    any of them
}