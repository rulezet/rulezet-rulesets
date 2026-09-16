rule TTP_XOR_MULT_DOSStub_5fbb {
  strings:
    $key_5fbb = { 0b d3 [2] 7f cb [2] 38 c9 [2] 7f d8 [2] 31 d4 [2] 3d de [2] 2a d5 [2] 31 9b [2] 0c }

  condition:
    any of them
}