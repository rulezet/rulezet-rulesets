rule TTP_XOR_MULT_DOSStub_af76 {
  strings:
    $key_af76 = { fb 1e [2] 8f 06 [2] c8 04 [2] 8f 15 [2] c1 19 [2] cd 13 [2] da 18 [2] c1 56 [2] fc }

  condition:
    any of them
}