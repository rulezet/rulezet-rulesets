rule TTP_XOR_MULT_DOSStub_af55 {
  strings:
    $key_af55 = { fb 3d [2] 8f 25 [2] c8 27 [2] 8f 36 [2] c1 3a [2] cd 30 [2] da 3b [2] c1 75 [2] fc }

  condition:
    any of them
}