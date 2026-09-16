rule TTP_XOR_MULT_DOSStub_af38 {
  strings:
    $key_af38 = { fb 50 [2] 8f 48 [2] c8 4a [2] 8f 5b [2] c1 57 [2] cd 5d [2] da 56 [2] c1 18 [2] fc }

  condition:
    any of them
}