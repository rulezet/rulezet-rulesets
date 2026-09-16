rule TTP_XOR_MULT_DOSStub_aae4 {
  strings:
    $key_aae4 = { fe 8c [2] 8a 94 [2] cd 96 [2] 8a 87 [2] c4 8b [2] c8 81 [2] df 8a [2] c4 c4 [2] f9 }

  condition:
    any of them
}