rule TTP_XOR_MULT_DOSStub_a369 {
  strings:
    $key_a369 = { f7 01 [2] 83 19 [2] c4 1b [2] 83 0a [2] cd 06 [2] c1 0c [2] d6 07 [2] cd 49 [2] f0 }

  condition:
    any of them
}