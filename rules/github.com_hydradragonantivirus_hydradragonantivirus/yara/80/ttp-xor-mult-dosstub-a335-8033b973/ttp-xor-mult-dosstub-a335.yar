rule TTP_XOR_MULT_DOSStub_a335 {
  strings:
    $key_a335 = { f7 5d [2] 83 45 [2] c4 47 [2] 83 56 [2] cd 5a [2] c1 50 [2] d6 5b [2] cd 15 [2] f0 }

  condition:
    any of them
}