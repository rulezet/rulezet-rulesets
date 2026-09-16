rule TTP_XOR_MULT_DOSStub_a311 {
  strings:
    $key_a311 = { f7 79 [2] 83 61 [2] c4 63 [2] 83 72 [2] cd 7e [2] c1 74 [2] d6 7f [2] cd 31 [2] f0 }

  condition:
    any of them
}