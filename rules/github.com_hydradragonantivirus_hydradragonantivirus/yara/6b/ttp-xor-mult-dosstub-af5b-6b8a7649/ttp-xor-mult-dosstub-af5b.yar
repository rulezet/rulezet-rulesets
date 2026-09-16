rule TTP_XOR_MULT_DOSStub_af5b {
  strings:
    $key_af5b = { fb 33 [2] 8f 2b [2] c8 29 [2] 8f 38 [2] c1 34 [2] cd 3e [2] da 35 [2] c1 7b [2] fc }

  condition:
    any of them
}