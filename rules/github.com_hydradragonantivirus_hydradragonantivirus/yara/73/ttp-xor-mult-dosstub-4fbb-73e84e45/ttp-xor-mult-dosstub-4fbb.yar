rule TTP_XOR_MULT_DOSStub_4fbb {
  strings:
    $key_4fbb = { 1b d3 [2] 6f cb [2] 28 c9 [2] 6f d8 [2] 21 d4 [2] 2d de [2] 3a d5 [2] 21 9b [2] 1c }

  condition:
    any of them
}