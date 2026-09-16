rule TTP_XOR_MULT_DOSStub_af7a {
  strings:
    $key_af7a = { fb 12 [2] 8f 0a [2] c8 08 [2] 8f 19 [2] c1 15 [2] cd 1f [2] da 14 [2] c1 5a [2] fc }

  condition:
    any of them
}