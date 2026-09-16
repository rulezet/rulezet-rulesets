rule TTP_XOR_MULT_DOSStub_af0a {
  strings:
    $key_af0a = { fb 62 [2] 8f 7a [2] c8 78 [2] 8f 69 [2] c1 65 [2] cd 6f [2] da 64 [2] c1 2a [2] fc }

  condition:
    any of them
}