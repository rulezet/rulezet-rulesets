rule TTP_XOR_MULT_DOSStub_babb {
  strings:
    $key_babb = { ee d3 [2] 9a cb [2] dd c9 [2] 9a d8 [2] d4 d4 [2] d8 de [2] cf d5 [2] d4 9b [2] e9 }

  condition:
    any of them
}