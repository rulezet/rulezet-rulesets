rule TTP_XOR_MULT_DOSStub_aa6b {
  strings:
    $key_aa6b = { fe 03 [2] 8a 1b [2] cd 19 [2] 8a 08 [2] c4 04 [2] c8 0e [2] df 05 [2] c4 4b [2] f9 }

  condition:
    any of them
}