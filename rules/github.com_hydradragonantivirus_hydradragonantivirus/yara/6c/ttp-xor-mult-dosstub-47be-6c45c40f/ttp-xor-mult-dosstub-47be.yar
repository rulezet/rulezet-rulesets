rule TTP_XOR_MULT_DOSStub_47be {
  strings:
    $key_47be = { 13 d6 [2] 67 ce [2] 20 cc [2] 67 dd [2] 29 d1 [2] 25 db [2] 32 d0 [2] 29 9e [2] 14 }

  condition:
    any of them
}