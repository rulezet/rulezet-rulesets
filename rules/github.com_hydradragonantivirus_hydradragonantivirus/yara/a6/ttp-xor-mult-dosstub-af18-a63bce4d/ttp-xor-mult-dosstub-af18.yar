rule TTP_XOR_MULT_DOSStub_af18 {
  strings:
    $key_af18 = { fb 70 [2] 8f 68 [2] c8 6a [2] 8f 7b [2] c1 77 [2] cd 7d [2] da 76 [2] c1 38 [2] fc }

  condition:
    any of them
}