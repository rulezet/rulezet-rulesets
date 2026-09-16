rule TTP_XOR_MULT_DOSStub_18be {
  strings:
    $key_18be = { 4c d6 [2] 38 ce [2] 7f cc [2] 38 dd [2] 76 d1 [2] 7a db [2] 6d d0 [2] 76 9e [2] 4b }

  condition:
    any of them
}