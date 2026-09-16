rule TTP_XOR_MULT_DOSStub_aff7 {
  strings:
    $key_aff7 = { fb 9f [2] 8f 87 [2] c8 85 [2] 8f 94 [2] c1 98 [2] cd 92 [2] da 99 [2] c1 d7 [2] fc }

  condition:
    any of them
}