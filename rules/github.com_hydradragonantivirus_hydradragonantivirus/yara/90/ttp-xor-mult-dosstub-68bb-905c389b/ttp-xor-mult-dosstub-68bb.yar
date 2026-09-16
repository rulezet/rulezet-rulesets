rule TTP_XOR_MULT_DOSStub_68bb {
  strings:
    $key_68bb = { 3c d3 [2] 48 cb [2] 0f c9 [2] 48 d8 [2] 06 d4 [2] 0a de [2] 1d d5 [2] 06 9b [2] 3b }

  condition:
    any of them
}