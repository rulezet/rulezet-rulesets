rule TTP_XOR_MULT_DOSStub_89be {
  strings:
    $key_89be = { dd d6 [2] a9 ce [2] ee cc [2] a9 dd [2] e7 d1 [2] eb db [2] fc d0 [2] e7 9e [2] da }

  condition:
    any of them
}