rule TTP_XOR_MULT_DOSStub_73be {
  strings:
    $key_73be = { 27 d6 [2] 53 ce [2] 14 cc [2] 53 dd [2] 1d d1 [2] 11 db [2] 06 d0 [2] 1d 9e [2] 20 }

  condition:
    any of them
}