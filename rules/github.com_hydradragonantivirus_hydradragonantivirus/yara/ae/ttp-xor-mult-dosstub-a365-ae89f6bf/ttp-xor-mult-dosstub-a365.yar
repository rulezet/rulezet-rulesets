rule TTP_XOR_MULT_DOSStub_a365 {
  strings:
    $key_a365 = { f7 0d [2] 83 15 [2] c4 17 [2] 83 06 [2] cd 0a [2] c1 00 [2] d6 0b [2] cd 45 [2] f0 }

  condition:
    any of them
}