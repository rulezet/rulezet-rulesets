rule TTP_XOR_MULT_DOSStub_03be {
  strings:
    $key_03be = { 57 d6 [2] 23 ce [2] 64 cc [2] 23 dd [2] 6d d1 [2] 61 db [2] 76 d0 [2] 6d 9e [2] 50 }

  condition:
    any of them
}