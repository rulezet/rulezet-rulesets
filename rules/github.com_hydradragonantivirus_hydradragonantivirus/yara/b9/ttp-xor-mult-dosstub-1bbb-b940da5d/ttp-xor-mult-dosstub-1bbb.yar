rule TTP_XOR_MULT_DOSStub_1bbb {
  strings:
    $key_1bbb = { 4f d3 [2] 3b cb [2] 7c c9 [2] 3b d8 [2] 75 d4 [2] 79 de [2] 6e d5 [2] 75 9b [2] 48 }

  condition:
    any of them
}