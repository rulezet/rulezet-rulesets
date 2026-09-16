rule TTP_XOR_MULT_DOSStub_af21 {
  strings:
    $key_af21 = { fb 49 [2] 8f 51 [2] c8 53 [2] 8f 42 [2] c1 4e [2] cd 44 [2] da 4f [2] c1 01 [2] fc }

  condition:
    any of them
}