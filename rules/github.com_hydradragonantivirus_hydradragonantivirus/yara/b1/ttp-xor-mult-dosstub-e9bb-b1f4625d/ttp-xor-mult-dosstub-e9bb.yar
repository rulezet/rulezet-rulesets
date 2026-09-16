rule TTP_XOR_MULT_DOSStub_e9bb {
  strings:
    $key_e9bb = { bd d3 [2] c9 cb [2] 8e c9 [2] c9 d8 [2] 87 d4 [2] 8b de [2] 9c d5 [2] 87 9b [2] ba }

  condition:
    any of them
}