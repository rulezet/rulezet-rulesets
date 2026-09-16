rule TTP_XOR_MULT_DOSStub_aaed {
  strings:
    $key_aaed = { fe 85 [2] 8a 9d [2] cd 9f [2] 8a 8e [2] c4 82 [2] c8 88 [2] df 83 [2] c4 cd [2] f9 }

  condition:
    any of them
}