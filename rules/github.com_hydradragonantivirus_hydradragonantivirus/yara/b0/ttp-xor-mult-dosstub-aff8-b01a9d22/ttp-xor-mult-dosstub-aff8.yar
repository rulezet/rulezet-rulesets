rule TTP_XOR_MULT_DOSStub_aff8 {
  strings:
    $key_aff8 = { fb 90 [2] 8f 88 [2] c8 8a [2] 8f 9b [2] c1 97 [2] cd 9d [2] da 96 [2] c1 d8 [2] fc }

  condition:
    any of them
}