rule TTP_XOR_MULT_DOSStub_a344 {
  strings:
    $key_a344 = { f7 2c [2] 83 34 [2] c4 36 [2] 83 27 [2] cd 2b [2] c1 21 [2] d6 2a [2] cd 64 [2] f0 }

  condition:
    any of them
}