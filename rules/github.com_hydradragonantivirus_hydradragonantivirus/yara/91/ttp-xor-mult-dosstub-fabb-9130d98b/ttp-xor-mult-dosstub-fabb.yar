rule TTP_XOR_MULT_DOSStub_fabb {
  strings:
    $key_fabb = { ae d3 [2] da cb [2] 9d c9 [2] da d8 [2] 94 d4 [2] 98 de [2] 8f d5 [2] 94 9b [2] a9 }

  condition:
    any of them
}