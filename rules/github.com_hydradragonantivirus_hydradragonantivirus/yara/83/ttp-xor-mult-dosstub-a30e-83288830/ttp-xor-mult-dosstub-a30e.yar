rule TTP_XOR_MULT_DOSStub_a30e {
  strings:
    $key_a30e = { f7 66 [2] 83 7e [2] c4 7c [2] 83 6d [2] cd 61 [2] c1 6b [2] d6 60 [2] cd 2e [2] f0 }

  condition:
    any of them
}