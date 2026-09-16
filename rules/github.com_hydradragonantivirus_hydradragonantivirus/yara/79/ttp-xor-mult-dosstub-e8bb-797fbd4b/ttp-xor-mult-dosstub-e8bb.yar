rule TTP_XOR_MULT_DOSStub_e8bb {
  strings:
    $key_e8bb = { bc d3 [2] c8 cb [2] 8f c9 [2] c8 d8 [2] 86 d4 [2] 8a de [2] 9d d5 [2] 86 9b [2] bb }

  condition:
    any of them
}