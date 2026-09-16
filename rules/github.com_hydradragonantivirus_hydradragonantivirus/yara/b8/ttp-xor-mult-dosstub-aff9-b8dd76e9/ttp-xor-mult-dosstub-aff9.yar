rule TTP_XOR_MULT_DOSStub_aff9 {
  strings:
    $key_aff9 = { fb 91 [2] 8f 89 [2] c8 8b [2] 8f 9a [2] c1 96 [2] cd 9c [2] da 97 [2] c1 d9 [2] fc }

  condition:
    any of them
}