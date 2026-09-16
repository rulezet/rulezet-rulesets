rule TTP_XOR_MULT_DOSStub_aabc {
  strings:
    $key_aabc = { fe d4 [2] 8a cc [2] cd ce [2] 8a df [2] c4 d3 [2] c8 d9 [2] df d2 [2] c4 9c [2] f9 }

  condition:
    any of them
}