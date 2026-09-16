rule TTP_XOR_MULT_DOSStub_af34 {
  strings:
    $key_af34 = { fb 5c [2] 8f 44 [2] c8 46 [2] 8f 57 [2] c1 5b [2] cd 51 [2] da 5a [2] c1 14 [2] fc }

  condition:
    any of them
}