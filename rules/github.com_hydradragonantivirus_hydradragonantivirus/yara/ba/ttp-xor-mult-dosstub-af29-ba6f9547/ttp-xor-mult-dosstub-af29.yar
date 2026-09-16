rule TTP_XOR_MULT_DOSStub_af29 {
  strings:
    $key_af29 = { fb 41 [2] 8f 59 [2] c8 5b [2] 8f 4a [2] c1 46 [2] cd 4c [2] da 47 [2] c1 09 [2] fc }

  condition:
    any of them
}