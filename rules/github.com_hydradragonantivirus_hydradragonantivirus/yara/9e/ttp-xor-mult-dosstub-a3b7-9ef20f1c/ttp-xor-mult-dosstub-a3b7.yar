rule TTP_XOR_MULT_DOSStub_a3b7 {
  strings:
    $key_a3b7 = { f7 df [2] 83 c7 [2] c4 c5 [2] 83 d4 [2] cd d8 [2] c1 d2 [2] d6 d9 [2] cd 97 [2] f0 }

  condition:
    any of them
}