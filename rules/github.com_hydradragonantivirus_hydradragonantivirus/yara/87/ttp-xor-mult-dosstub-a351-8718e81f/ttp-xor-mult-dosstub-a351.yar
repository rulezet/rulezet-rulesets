rule TTP_XOR_MULT_DOSStub_a351 {
  strings:
    $key_a351 = { f7 39 [2] 83 21 [2] c4 23 [2] 83 32 [2] cd 3e [2] c1 34 [2] d6 3f [2] cd 71 [2] f0 }

  condition:
    any of them
}