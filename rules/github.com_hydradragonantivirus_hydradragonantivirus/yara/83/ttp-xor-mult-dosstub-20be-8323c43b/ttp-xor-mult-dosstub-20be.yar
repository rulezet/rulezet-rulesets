rule TTP_XOR_MULT_DOSStub_20be {
  strings:
    $key_20be = { 74 d6 [2] 00 ce [2] 47 cc [2] 00 dd [2] 4e d1 [2] 42 db [2] 55 d0 [2] 4e 9e [2] 73 }

  condition:
    any of them
}