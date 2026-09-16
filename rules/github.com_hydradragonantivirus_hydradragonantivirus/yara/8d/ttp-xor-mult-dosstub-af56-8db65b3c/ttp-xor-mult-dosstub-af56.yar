rule TTP_XOR_MULT_DOSStub_af56 {
  strings:
    $key_af56 = { fb 3e [2] 8f 26 [2] c8 24 [2] 8f 35 [2] c1 39 [2] cd 33 [2] da 38 [2] c1 76 [2] fc }

  condition:
    any of them
}