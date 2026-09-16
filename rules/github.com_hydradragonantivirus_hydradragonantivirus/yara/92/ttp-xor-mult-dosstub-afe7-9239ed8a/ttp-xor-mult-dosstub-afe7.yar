rule TTP_XOR_MULT_DOSStub_afe7 {
  strings:
    $key_afe7 = { fb 8f [2] 8f 97 [2] c8 95 [2] 8f 84 [2] c1 88 [2] cd 82 [2] da 89 [2] c1 c7 [2] fc }

  condition:
    any of them
}