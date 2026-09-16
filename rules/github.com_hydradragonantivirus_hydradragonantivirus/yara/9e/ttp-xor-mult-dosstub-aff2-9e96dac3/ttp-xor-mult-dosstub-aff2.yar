rule TTP_XOR_MULT_DOSStub_aff2 {
  strings:
    $key_aff2 = { fb 9a [2] 8f 82 [2] c8 80 [2] 8f 91 [2] c1 9d [2] cd 97 [2] da 9c [2] c1 d2 [2] fc }

  condition:
    any of them
}