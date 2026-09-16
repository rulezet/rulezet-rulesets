rule TTP_XOR_MULT_DOSStub_aff5 {
  strings:
    $key_aff5 = { fb 9d [2] 8f 85 [2] c8 87 [2] 8f 96 [2] c1 9a [2] cd 90 [2] da 9b [2] c1 d5 [2] fc }

  condition:
    any of them
}