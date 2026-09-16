rule TTP_XOR_MULT_DOSStub_af77 {
  strings:
    $key_af77 = { fb 1f [2] 8f 07 [2] c8 05 [2] 8f 14 [2] c1 18 [2] cd 12 [2] da 19 [2] c1 57 [2] fc }

  condition:
    any of them
}