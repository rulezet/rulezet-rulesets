rule TTP_XOR_MULT_DOSStub_a30c {
  strings:
    $key_a30c = { f7 64 [2] 83 7c [2] c4 7e [2] 83 6f [2] cd 63 [2] c1 69 [2] d6 62 [2] cd 2c [2] f0 }

  condition:
    any of them
}