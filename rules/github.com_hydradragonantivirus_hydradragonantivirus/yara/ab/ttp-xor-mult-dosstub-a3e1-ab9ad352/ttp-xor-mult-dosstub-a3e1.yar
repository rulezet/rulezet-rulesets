rule TTP_XOR_MULT_DOSStub_a3e1 {
  strings:
    $key_a3e1 = { f7 89 [2] 83 91 [2] c4 93 [2] 83 82 [2] cd 8e [2] c1 84 [2] d6 8f [2] cd c1 [2] f0 }

  condition:
    any of them
}