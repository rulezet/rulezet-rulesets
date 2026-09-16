rule TTP_XOR_MULT_DOSStub_0abb {
  strings:
    $key_0abb = { 5e d3 [2] 2a cb [2] 6d c9 [2] 2a d8 [2] 64 d4 [2] 68 de [2] 7f d5 [2] 64 9b [2] 59 }

  condition:
    any of them
}