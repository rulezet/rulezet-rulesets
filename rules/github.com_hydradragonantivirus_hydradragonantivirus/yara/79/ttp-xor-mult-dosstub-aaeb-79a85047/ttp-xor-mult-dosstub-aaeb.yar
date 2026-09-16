rule TTP_XOR_MULT_DOSStub_aaeb {
  strings:
    $key_aaeb = { fe 83 [2] 8a 9b [2] cd 99 [2] 8a 88 [2] c4 84 [2] c8 8e [2] df 85 [2] c4 cb [2] f9 }

  condition:
    any of them
}