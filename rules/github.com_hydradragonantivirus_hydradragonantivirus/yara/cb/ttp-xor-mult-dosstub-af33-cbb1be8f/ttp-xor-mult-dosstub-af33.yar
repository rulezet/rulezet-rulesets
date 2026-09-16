rule TTP_XOR_MULT_DOSStub_af33 {
  strings:
    $key_af33 = { fb 5b [2] 8f 43 [2] c8 41 [2] 8f 50 [2] c1 5c [2] cd 56 [2] da 5d [2] c1 13 [2] fc }

  condition:
    any of them
}