rule TTP_XOR_MULT_DOSStub_af66 {
  strings:
    $key_af66 = { fb 0e [2] 8f 16 [2] c8 14 [2] 8f 05 [2] c1 09 [2] cd 03 [2] da 08 [2] c1 46 [2] fc }

  condition:
    any of them
}