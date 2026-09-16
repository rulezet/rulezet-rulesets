rule TTP_XOR_MULT_DOSStub_69bb {
  strings:
    $key_69bb = { 3d d3 [2] 49 cb [2] 0e c9 [2] 49 d8 [2] 07 d4 [2] 0b de [2] 1c d5 [2] 07 9b [2] 3a }

  condition:
    any of them
}