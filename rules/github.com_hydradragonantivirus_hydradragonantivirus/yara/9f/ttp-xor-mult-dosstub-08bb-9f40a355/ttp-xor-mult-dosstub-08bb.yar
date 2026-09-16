rule TTP_XOR_MULT_DOSStub_08bb {
  strings:
    $key_08bb = { 5c d3 [2] 28 cb [2] 6f c9 [2] 28 d8 [2] 66 d4 [2] 6a de [2] 7d d5 [2] 66 9b [2] 5b }

  condition:
    any of them
}