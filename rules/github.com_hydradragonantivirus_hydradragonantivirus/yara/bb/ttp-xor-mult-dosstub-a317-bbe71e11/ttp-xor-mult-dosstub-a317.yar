rule TTP_XOR_MULT_DOSStub_a317 {
  strings:
    $key_a317 = { f7 7f [2] 83 67 [2] c4 65 [2] 83 74 [2] cd 78 [2] c1 72 [2] d6 79 [2] cd 37 [2] f0 }

  condition:
    any of them
}