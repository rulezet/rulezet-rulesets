rule TTP_XOR_MULT_DOSStub_7fbb {
  strings:
    $key_7fbb = { 2b d3 [2] 5f cb [2] 18 c9 [2] 5f d8 [2] 11 d4 [2] 1d de [2] 0a d5 [2] 11 9b [2] 2c }

  condition:
    any of them
}