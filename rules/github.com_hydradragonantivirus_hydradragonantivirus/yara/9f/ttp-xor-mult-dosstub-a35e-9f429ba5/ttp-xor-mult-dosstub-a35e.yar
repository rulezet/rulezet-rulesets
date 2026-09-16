rule TTP_XOR_MULT_DOSStub_a35e {
  strings:
    $key_a35e = { f7 36 [2] 83 2e [2] c4 2c [2] 83 3d [2] cd 31 [2] c1 3b [2] d6 30 [2] cd 7e [2] f0 }

  condition:
    any of them
}