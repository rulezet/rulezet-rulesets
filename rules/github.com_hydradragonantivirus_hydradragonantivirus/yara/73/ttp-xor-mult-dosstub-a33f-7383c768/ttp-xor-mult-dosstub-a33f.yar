rule TTP_XOR_MULT_DOSStub_a33f {
  strings:
    $key_a33f = { f7 57 [2] 83 4f [2] c4 4d [2] 83 5c [2] cd 50 [2] c1 5a [2] d6 51 [2] cd 1f [2] f0 }

  condition:
    any of them
}