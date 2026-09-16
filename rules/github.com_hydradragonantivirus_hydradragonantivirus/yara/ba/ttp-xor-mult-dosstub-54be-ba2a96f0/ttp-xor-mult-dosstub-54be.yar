rule TTP_XOR_MULT_DOSStub_54be {
  strings:
    $key_54be = { 00 d6 [2] 74 ce [2] 33 cc [2] 74 dd [2] 3a d1 [2] 36 db [2] 21 d0 [2] 3a 9e [2] 07 }

  condition:
    any of them
}