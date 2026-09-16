rule TTP_XOR_MULT_DOSStub_a33e {
  strings:
    $key_a33e = { f7 56 [2] 83 4e [2] c4 4c [2] 83 5d [2] cd 51 [2] c1 5b [2] d6 50 [2] cd 1e [2] f0 }

  condition:
    any of them
}