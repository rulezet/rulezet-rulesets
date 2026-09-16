rule TTP_XOR_MULT_DOSStub_2ebb {
  strings:
    $key_2ebb = { 7a d3 [2] 0e cb [2] 49 c9 [2] 0e d8 [2] 40 d4 [2] 4c de [2] 5b d5 [2] 40 9b [2] 7d }

  condition:
    any of them
}