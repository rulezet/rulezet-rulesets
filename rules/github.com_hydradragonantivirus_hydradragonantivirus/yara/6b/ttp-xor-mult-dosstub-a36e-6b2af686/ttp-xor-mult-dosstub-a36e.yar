rule TTP_XOR_MULT_DOSStub_a36e {
  strings:
    $key_a36e = { f7 06 [2] 83 1e [2] c4 1c [2] 83 0d [2] cd 01 [2] c1 0b [2] d6 00 [2] cd 4e [2] f0 }

  condition:
    any of them
}