rule TTP_XOR_MULT_DOSStub_a316 {
  strings:
    $key_a316 = { f7 7e [2] 83 66 [2] c4 64 [2] 83 75 [2] cd 79 [2] c1 73 [2] d6 78 [2] cd 36 [2] f0 }

  condition:
    any of them
}