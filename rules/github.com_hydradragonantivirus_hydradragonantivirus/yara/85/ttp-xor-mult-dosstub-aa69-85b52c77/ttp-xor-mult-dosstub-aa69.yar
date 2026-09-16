rule TTP_XOR_MULT_DOSStub_aa69 {
  strings:
    $key_aa69 = { fe 01 [2] 8a 19 [2] cd 1b [2] 8a 0a [2] c4 06 [2] c8 0c [2] df 07 [2] c4 49 [2] f9 }

  condition:
    any of them
}