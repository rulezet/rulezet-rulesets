rule TTP_XOR_MULT_DOSStub_48be {
  strings:
    $key_48be = { 1c d6 [2] 68 ce [2] 2f cc [2] 68 dd [2] 26 d1 [2] 2a db [2] 3d d0 [2] 26 9e [2] 1b }

  condition:
    any of them
}