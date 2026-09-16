rule TTP_XOR_MULT_DOSStub_a337 {
  strings:
    $key_a337 = { f7 5f [2] 83 47 [2] c4 45 [2] 83 54 [2] cd 58 [2] c1 52 [2] d6 59 [2] cd 17 [2] f0 }

  condition:
    any of them
}