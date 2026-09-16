rule TTP_XOR_MULT_DOSStub_5abb {
  strings:
    $key_5abb = { 0e d3 [2] 7a cb [2] 3d c9 [2] 7a d8 [2] 34 d4 [2] 38 de [2] 2f d5 [2] 34 9b [2] 09 }

  condition:
    any of them
}