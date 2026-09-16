rule TTP_XOR_MULT_DOSStub_aaef {
  strings:
    $key_aaef = { fe 87 [2] 8a 9f [2] cd 9d [2] 8a 8c [2] c4 80 [2] c8 8a [2] df 81 [2] c4 cf [2] f9 }

  condition:
    any of them
}