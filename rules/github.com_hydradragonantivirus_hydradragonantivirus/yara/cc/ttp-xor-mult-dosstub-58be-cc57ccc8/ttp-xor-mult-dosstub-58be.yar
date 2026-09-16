rule TTP_XOR_MULT_DOSStub_58be {
  strings:
    $key_58be = { 0c d6 [2] 78 ce [2] 3f cc [2] 78 dd [2] 36 d1 [2] 3a db [2] 2d d0 [2] 36 9e [2] 0b }

  condition:
    any of them
}