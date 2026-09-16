rule TTP_XOR_MULT_DOSStub_af08 {
  strings:
    $key_af08 = { fb 60 [2] 8f 78 [2] c8 7a [2] 8f 6b [2] c1 67 [2] cd 6d [2] da 66 [2] c1 28 [2] fc }

  condition:
    any of them
}