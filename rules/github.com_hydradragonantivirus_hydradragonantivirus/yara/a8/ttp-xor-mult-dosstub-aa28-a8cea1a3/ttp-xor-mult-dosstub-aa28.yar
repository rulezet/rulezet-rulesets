rule TTP_XOR_MULT_DOSStub_aa28 {
  strings:
    $key_aa28 = { fe 40 [2] 8a 58 [2] cd 5a [2] 8a 4b [2] c4 47 [2] c8 4d [2] df 46 [2] c4 08 [2] f9 }

  condition:
    any of them
}