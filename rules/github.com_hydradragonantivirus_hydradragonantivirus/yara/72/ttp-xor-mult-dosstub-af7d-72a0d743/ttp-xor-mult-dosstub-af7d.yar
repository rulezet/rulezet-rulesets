rule TTP_XOR_MULT_DOSStub_af7d {
  strings:
    $key_af7d = { fb 15 [2] 8f 0d [2] c8 0f [2] 8f 1e [2] c1 12 [2] cd 18 [2] da 13 [2] c1 5d [2] fc }

  condition:
    any of them
}