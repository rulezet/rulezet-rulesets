rule TTP_XOR_MULT_DOSStub_7ebb {
  strings:
    $key_7ebb = { 2a d3 [2] 5e cb [2] 19 c9 [2] 5e d8 [2] 10 d4 [2] 1c de [2] 0b d5 [2] 10 9b [2] 2d }

  condition:
    any of them
}