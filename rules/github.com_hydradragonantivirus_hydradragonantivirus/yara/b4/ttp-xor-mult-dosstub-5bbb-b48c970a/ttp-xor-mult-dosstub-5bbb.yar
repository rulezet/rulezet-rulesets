rule TTP_XOR_MULT_DOSStub_5bbb {
  strings:
    $key_5bbb = { 0f d3 [2] 7b cb [2] 3c c9 [2] 7b d8 [2] 35 d4 [2] 39 de [2] 2e d5 [2] 35 9b [2] 08 }

  condition:
    any of them
}