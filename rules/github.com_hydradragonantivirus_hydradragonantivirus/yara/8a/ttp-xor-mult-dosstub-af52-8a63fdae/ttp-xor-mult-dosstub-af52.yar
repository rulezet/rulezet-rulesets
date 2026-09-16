rule TTP_XOR_MULT_DOSStub_af52 {
  strings:
    $key_af52 = { fb 3a [2] 8f 22 [2] c8 20 [2] 8f 31 [2] c1 3d [2] cd 37 [2] da 3c [2] c1 72 [2] fc }

  condition:
    any of them
}