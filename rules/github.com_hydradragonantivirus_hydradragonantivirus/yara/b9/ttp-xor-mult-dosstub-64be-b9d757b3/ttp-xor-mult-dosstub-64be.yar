rule TTP_XOR_MULT_DOSStub_64be {
  strings:
    $key_64be = { 30 d6 [2] 44 ce [2] 03 cc [2] 44 dd [2] 0a d1 [2] 06 db [2] 11 d0 [2] 0a 9e [2] 37 }

  condition:
    any of them
}