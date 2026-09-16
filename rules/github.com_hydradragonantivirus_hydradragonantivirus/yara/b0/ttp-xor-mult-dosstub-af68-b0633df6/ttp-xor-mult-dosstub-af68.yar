rule TTP_XOR_MULT_DOSStub_af68 {
  strings:
    $key_af68 = { fb 00 [2] 8f 18 [2] c8 1a [2] 8f 0b [2] c1 07 [2] cd 0d [2] da 06 [2] c1 48 [2] fc }

  condition:
    any of them
}