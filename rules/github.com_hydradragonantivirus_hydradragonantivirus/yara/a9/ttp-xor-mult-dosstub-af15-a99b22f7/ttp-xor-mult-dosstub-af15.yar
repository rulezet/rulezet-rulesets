rule TTP_XOR_MULT_DOSStub_af15 {
  strings:
    $key_af15 = { fb 7d [2] 8f 65 [2] c8 67 [2] 8f 76 [2] c1 7a [2] cd 70 [2] da 7b [2] c1 35 [2] fc }

  condition:
    any of them
}