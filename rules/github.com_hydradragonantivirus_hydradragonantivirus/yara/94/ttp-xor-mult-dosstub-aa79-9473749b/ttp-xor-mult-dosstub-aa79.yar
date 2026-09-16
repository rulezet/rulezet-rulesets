rule TTP_XOR_MULT_DOSStub_aa79 {
  strings:
    $key_aa79 = { fe 11 [2] 8a 09 [2] cd 0b [2] 8a 1a [2] c4 16 [2] c8 1c [2] df 17 [2] c4 59 [2] f9 }

  condition:
    any of them
}