rule TTP_XOR_MULT_DOSStub_69bc {
  strings:
    $key_69bc = { 3d d4 [2] 49 cc [2] 0e ce [2] 49 df [2] 07 d3 [2] 0b d9 [2] 1c d2 [2] 07 9c [2] 3a }

  condition:
    any of them
}