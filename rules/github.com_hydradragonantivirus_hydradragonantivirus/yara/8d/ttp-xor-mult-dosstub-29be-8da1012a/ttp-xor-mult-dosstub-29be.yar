rule TTP_XOR_MULT_DOSStub_29be {
  strings:
    $key_29be = { 7d d6 [2] 09 ce [2] 4e cc [2] 09 dd [2] 47 d1 [2] 4b db [2] 5c d0 [2] 47 9e [2] 7a }

  condition:
    any of them
}