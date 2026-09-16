rule TTP_XOR_MULT_DOSStub_afe5 {
  strings:
    $key_afe5 = { fb 8d [2] 8f 95 [2] c8 97 [2] 8f 86 [2] c1 8a [2] cd 80 [2] da 8b [2] c1 c5 [2] fc }

  condition:
    any of them
}