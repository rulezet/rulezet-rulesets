rule TTP_XOR_MULT_DOSStub_a3bb {
  strings:
    $key_a3bb = { f7 d3 [2] 83 cb [2] c4 c9 [2] 83 d8 [2] cd d4 [2] c1 de [2] d6 d5 [2] cd 9b [2] f0 }

  condition:
    any of them
}