rule TTP_XOR_MULT_DOSStub_4abb {
  strings:
    $key_4abb = { 1e d3 [2] 6a cb [2] 2d c9 [2] 6a d8 [2] 24 d4 [2] 28 de [2] 3f d5 [2] 24 9b [2] 19 }

  condition:
    any of them
}