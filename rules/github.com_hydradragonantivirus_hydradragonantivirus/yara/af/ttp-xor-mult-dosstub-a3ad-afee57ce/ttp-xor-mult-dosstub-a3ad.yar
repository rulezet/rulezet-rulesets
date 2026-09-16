rule TTP_XOR_MULT_DOSStub_a3ad {
  strings:
    $key_a3ad = { f7 c5 [2] 83 dd [2] c4 df [2] 83 ce [2] cd c2 [2] c1 c8 [2] d6 c3 [2] cd 8d [2] f0 }

  condition:
    any of them
}