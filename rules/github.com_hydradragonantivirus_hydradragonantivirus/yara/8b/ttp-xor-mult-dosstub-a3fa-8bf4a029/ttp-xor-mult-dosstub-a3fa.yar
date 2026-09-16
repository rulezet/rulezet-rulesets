rule TTP_XOR_MULT_DOSStub_a3fa {
  strings:
    $key_a3fa = { f7 92 [2] 83 8a [2] c4 88 [2] 83 99 [2] cd 95 [2] c1 9f [2] d6 94 [2] cd da [2] f0 }

  condition:
    any of them
}