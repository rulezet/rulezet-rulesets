rule TTP_XOR_MULT_DOSStub_afe3 {
  strings:
    $key_afe3 = { fb 8b [2] 8f 93 [2] c8 91 [2] 8f 80 [2] c1 8c [2] cd 86 [2] da 8d [2] c1 c3 [2] fc }

  condition:
    any of them
}