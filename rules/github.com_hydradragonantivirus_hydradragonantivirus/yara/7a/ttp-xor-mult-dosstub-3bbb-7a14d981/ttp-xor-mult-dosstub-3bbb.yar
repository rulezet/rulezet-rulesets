rule TTP_XOR_MULT_DOSStub_3bbb {
  strings:
    $key_3bbb = { 6f d3 [2] 1b cb [2] 5c c9 [2] 1b d8 [2] 55 d4 [2] 59 de [2] 4e d5 [2] 55 9b [2] 68 }

  condition:
    any of them
}