rule TTP_XOR_MULT_DOSStub_09be {
  strings:
    $key_09be = { 5d d6 [2] 29 ce [2] 6e cc [2] 29 dd [2] 67 d1 [2] 6b db [2] 7c d0 [2] 67 9e [2] 5a }

  condition:
    any of them
}