rule TTP_XOR_MULT_DOSStub_af44 {
  strings:
    $key_af44 = { fb 2c [2] 8f 34 [2] c8 36 [2] 8f 27 [2] c1 2b [2] cd 21 [2] da 2a [2] c1 64 [2] fc }

  condition:
    any of them
}