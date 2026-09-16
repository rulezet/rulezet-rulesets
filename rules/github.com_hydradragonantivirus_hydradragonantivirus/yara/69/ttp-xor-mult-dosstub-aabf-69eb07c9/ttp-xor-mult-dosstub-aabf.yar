rule TTP_XOR_MULT_DOSStub_aabf {
  strings:
    $key_aabf = { fe d7 [2] 8a cf [2] cd cd [2] 8a dc [2] c4 d0 [2] c8 da [2] df d1 [2] c4 9f [2] f9 }

  condition:
    any of them
}