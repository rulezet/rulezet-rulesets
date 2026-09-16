rule TTP_XOR_MULT_DOSStub_afe6 {
  strings:
    $key_afe6 = { fb 8e [2] 8f 96 [2] c8 94 [2] 8f 85 [2] c1 89 [2] cd 83 [2] da 88 [2] c1 c6 [2] fc }

  condition:
    any of them
}