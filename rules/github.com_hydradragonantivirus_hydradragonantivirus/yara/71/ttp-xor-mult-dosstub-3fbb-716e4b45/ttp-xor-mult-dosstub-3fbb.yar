rule TTP_XOR_MULT_DOSStub_3fbb {
  strings:
    $key_3fbb = { 6b d3 [2] 1f cb [2] 58 c9 [2] 1f d8 [2] 51 d4 [2] 5d de [2] 4a d5 [2] 51 9b [2] 6c }

  condition:
    any of them
}