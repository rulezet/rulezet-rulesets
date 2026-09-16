rule TTP_XOR_MULT_DOSStub_aa3b {
  strings:
    $key_aa3b = { fe 53 [2] 8a 4b [2] cd 49 [2] 8a 58 [2] c4 54 [2] c8 5e [2] df 55 [2] c4 1b [2] f9 }

  condition:
    any of them
}