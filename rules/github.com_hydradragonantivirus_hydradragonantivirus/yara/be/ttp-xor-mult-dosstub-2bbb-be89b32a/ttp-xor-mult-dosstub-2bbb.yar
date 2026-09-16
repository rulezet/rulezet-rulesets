rule TTP_XOR_MULT_DOSStub_2bbb {
  strings:
    $key_2bbb = { 7f d3 [2] 0b cb [2] 4c c9 [2] 0b d8 [2] 45 d4 [2] 49 de [2] 5e d5 [2] 45 9b [2] 78 }

  condition:
    any of them
}