rule TTP_XOR_MULT_DOSStub_a37b {
  strings:
    $key_a37b = { f7 13 [2] 83 0b [2] c4 09 [2] 83 18 [2] cd 14 [2] c1 1e [2] d6 15 [2] cd 5b [2] f0 }

  condition:
    any of them
}