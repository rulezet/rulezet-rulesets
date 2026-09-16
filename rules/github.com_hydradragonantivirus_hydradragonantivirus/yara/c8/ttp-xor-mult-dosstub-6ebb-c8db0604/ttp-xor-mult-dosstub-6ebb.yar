rule TTP_XOR_MULT_DOSStub_6ebb {
  strings:
    $key_6ebb = { 3a d3 [2] 4e cb [2] 09 c9 [2] 4e d8 [2] 00 d4 [2] 0c de [2] 1b d5 [2] 00 9b [2] 3d }

  condition:
    any of them
}