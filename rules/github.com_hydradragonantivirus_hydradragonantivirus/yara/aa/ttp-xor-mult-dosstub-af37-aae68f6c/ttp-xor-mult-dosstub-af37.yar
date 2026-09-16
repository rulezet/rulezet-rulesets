rule TTP_XOR_MULT_DOSStub_af37 {
  strings:
    $key_af37 = { fb 5f [2] 8f 47 [2] c8 45 [2] 8f 54 [2] c1 58 [2] cd 52 [2] da 59 [2] c1 17 [2] fc }

  condition:
    any of them
}