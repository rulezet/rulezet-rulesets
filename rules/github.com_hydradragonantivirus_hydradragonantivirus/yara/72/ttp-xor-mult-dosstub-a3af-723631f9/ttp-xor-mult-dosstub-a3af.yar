rule TTP_XOR_MULT_DOSStub_a3af {
  strings:
    $key_a3af = { f7 c7 [2] 83 df [2] c4 dd [2] 83 cc [2] cd c0 [2] c1 ca [2] d6 c1 [2] cd 8f [2] f0 }

  condition:
    any of them
}