rule TTP_XOR_MULT_DOSStub_a3ba {
  strings:
    $key_a3ba = { f7 d2 [2] 83 ca [2] c4 c8 [2] 83 d9 [2] cd d5 [2] c1 df [2] d6 d4 [2] cd 9a [2] f0 }

  condition:
    any of them
}