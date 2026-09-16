rule TTP_XOR_MULT_DOSStub_aa0c {
  strings:
    $key_aa0c = { fe 64 [2] 8a 7c [2] cd 7e [2] 8a 6f [2] c4 63 [2] c8 69 [2] df 62 [2] c4 2c [2] f9 }

  condition:
    any of them
}