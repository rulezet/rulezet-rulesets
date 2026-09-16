rule TTP_XOR_MULT_DOSStub_af42 {
  strings:
    $key_af42 = { fb 2a [2] 8f 32 [2] c8 30 [2] 8f 21 [2] c1 2d [2] cd 27 [2] da 2c [2] c1 62 [2] fc }

  condition:
    any of them
}