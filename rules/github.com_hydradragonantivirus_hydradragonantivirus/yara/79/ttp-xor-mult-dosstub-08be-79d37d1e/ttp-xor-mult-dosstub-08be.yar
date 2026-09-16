rule TTP_XOR_MULT_DOSStub_08be {
  strings:
    $key_08be = { 5c d6 [2] 28 ce [2] 6f cc [2] 28 dd [2] 66 d1 [2] 6a db [2] 7d d0 [2] 66 9e [2] 5b }

  condition:
    any of them
}