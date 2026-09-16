rule TTP_XOR_MULT_DOSStub_a3bc {
  strings:
    $key_a3bc = { f7 d4 [2] 83 cc [2] c4 ce [2] 83 df [2] cd d3 [2] c1 d9 [2] d6 d2 [2] cd 9c [2] f0 }

  condition:
    any of them
}