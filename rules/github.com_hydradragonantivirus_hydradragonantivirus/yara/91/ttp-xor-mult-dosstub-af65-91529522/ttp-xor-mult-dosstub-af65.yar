rule TTP_XOR_MULT_DOSStub_af65 {
  strings:
    $key_af65 = { fb 0d [2] 8f 15 [2] c8 17 [2] 8f 06 [2] c1 0a [2] cd 00 [2] da 0b [2] c1 45 [2] fc }

  condition:
    any of them
}