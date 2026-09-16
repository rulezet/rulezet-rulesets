rule TTP_XOR_MULT_DOSStub_a3eb {
  strings:
    $key_a3eb = { f7 83 [2] 83 9b [2] c4 99 [2] 83 88 [2] cd 84 [2] c1 8e [2] d6 85 [2] cd cb [2] f0 }

  condition:
    any of them
}