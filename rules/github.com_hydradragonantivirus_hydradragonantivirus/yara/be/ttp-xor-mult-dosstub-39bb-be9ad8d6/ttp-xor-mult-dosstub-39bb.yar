rule TTP_XOR_MULT_DOSStub_39bb {
  strings:
    $key_39bb = { 6d d3 [2] 19 cb [2] 5e c9 [2] 19 d8 [2] 57 d4 [2] 5b de [2] 4c d5 [2] 57 9b [2] 6a }

  condition:
    any of them
}