rule TTP_XOR_MULT_DOSStub_59bb {
  strings:
    $key_59bb = { 0d d3 [2] 79 cb [2] 3e c9 [2] 79 d8 [2] 37 d4 [2] 3b de [2] 2c d5 [2] 37 9b [2] 0a }

  condition:
    any of them
}