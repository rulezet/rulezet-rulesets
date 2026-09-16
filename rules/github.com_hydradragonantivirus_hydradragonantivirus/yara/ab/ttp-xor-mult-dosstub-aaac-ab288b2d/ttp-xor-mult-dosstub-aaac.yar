rule TTP_XOR_MULT_DOSStub_aaac {
  strings:
    $key_aaac = { fe c4 [2] 8a dc [2] cd de [2] 8a cf [2] c4 c3 [2] c8 c9 [2] df c2 [2] c4 8c [2] f9 }

  condition:
    any of them
}