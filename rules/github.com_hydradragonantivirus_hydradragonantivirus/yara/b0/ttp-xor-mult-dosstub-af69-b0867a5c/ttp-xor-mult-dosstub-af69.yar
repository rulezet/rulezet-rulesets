rule TTP_XOR_MULT_DOSStub_af69 {
  strings:
    $key_af69 = { fb 01 [2] 8f 19 [2] c8 1b [2] 8f 0a [2] c1 06 [2] cd 0c [2] da 07 [2] c1 49 [2] fc }

  condition:
    any of them
}