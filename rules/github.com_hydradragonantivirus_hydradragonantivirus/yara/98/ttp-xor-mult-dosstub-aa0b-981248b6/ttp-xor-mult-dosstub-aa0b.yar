rule TTP_XOR_MULT_DOSStub_aa0b {
  strings:
    $key_aa0b = { fe 63 [2] 8a 7b [2] cd 79 [2] 8a 68 [2] c4 64 [2] c8 6e [2] df 65 [2] c4 2b [2] f9 }

  condition:
    any of them
}