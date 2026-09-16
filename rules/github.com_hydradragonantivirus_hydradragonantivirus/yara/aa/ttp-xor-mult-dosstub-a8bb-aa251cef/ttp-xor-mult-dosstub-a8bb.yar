rule TTP_XOR_MULT_DOSStub_a8bb {
  strings:
    $key_a8bb = { fc d3 [2] 88 cb [2] cf c9 [2] 88 d8 [2] c6 d4 [2] ca de [2] dd d5 [2] c6 9b [2] fb }

  condition:
    any of them
}