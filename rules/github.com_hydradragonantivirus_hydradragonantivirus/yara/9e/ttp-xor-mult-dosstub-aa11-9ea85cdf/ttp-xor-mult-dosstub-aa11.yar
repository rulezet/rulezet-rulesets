rule TTP_XOR_MULT_DOSStub_aa11 {
  strings:
    $key_aa11 = { fe 79 [2] 8a 61 [2] cd 63 [2] 8a 72 [2] c4 7e [2] c8 74 [2] df 7f [2] c4 31 [2] f9 }

  condition:
    any of them
}