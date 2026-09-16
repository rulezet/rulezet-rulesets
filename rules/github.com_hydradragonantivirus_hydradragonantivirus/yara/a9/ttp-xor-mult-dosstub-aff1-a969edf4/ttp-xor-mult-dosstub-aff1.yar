rule TTP_XOR_MULT_DOSStub_aff1 {
  strings:
    $key_aff1 = { fb 99 [2] 8f 81 [2] c8 83 [2] 8f 92 [2] c1 9e [2] cd 94 [2] da 9f [2] c1 d1 [2] fc }

  condition:
    any of them
}