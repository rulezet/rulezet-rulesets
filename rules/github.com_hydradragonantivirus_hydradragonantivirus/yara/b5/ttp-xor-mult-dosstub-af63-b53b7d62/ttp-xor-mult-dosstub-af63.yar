rule TTP_XOR_MULT_DOSStub_af63 {
  strings:
    $key_af63 = { fb 0b [2] 8f 13 [2] c8 11 [2] 8f 00 [2] c1 0c [2] cd 06 [2] da 0d [2] c1 43 [2] fc }

  condition:
    any of them
}