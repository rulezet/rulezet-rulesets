rule TTP_XOR_MULT_DOSStub_af4a {
  strings:
    $key_af4a = { fb 22 [2] 8f 3a [2] c8 38 [2] 8f 29 [2] c1 25 [2] cd 2f [2] da 24 [2] c1 6a [2] fc }

  condition:
    any of them
}