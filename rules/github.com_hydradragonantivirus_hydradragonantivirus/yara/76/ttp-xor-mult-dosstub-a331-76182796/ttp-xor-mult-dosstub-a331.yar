rule TTP_XOR_MULT_DOSStub_a331 {
  strings:
    $key_a331 = { f7 59 [2] 83 41 [2] c4 43 [2] 83 52 [2] cd 5e [2] c1 54 [2] d6 5f [2] cd 11 [2] f0 }

  condition:
    any of them
}