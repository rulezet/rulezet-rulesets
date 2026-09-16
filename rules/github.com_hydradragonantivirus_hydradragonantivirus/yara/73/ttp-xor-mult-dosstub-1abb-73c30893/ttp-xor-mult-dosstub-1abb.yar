rule TTP_XOR_MULT_DOSStub_1abb {
  strings:
    $key_1abb = { 4e d3 [2] 3a cb [2] 7d c9 [2] 3a d8 [2] 74 d4 [2] 78 de [2] 6f d5 [2] 74 9b [2] 49 }

  condition:
    any of them
}