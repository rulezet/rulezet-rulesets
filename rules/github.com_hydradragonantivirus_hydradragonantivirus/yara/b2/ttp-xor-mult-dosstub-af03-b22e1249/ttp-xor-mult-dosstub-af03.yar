rule TTP_XOR_MULT_DOSStub_af03 {
  strings:
    $key_af03 = { fb 6b [2] 8f 73 [2] c8 71 [2] 8f 60 [2] c1 6c [2] cd 66 [2] da 6d [2] c1 23 [2] fc }

  condition:
    any of them
}