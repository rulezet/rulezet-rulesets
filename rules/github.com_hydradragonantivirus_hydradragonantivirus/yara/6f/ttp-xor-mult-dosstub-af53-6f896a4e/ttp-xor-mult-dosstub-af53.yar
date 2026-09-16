rule TTP_XOR_MULT_DOSStub_af53 {
  strings:
    $key_af53 = { fb 3b [2] 8f 23 [2] c8 21 [2] 8f 30 [2] c1 3c [2] cd 36 [2] da 3d [2] c1 73 [2] fc }

  condition:
    any of them
}