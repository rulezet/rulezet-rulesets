rule TTP_XOR_MULT_DOSStub_af16 {
  strings:
    $key_af16 = { fb 7e [2] 8f 66 [2] c8 64 [2] 8f 75 [2] c1 79 [2] cd 73 [2] da 78 [2] c1 36 [2] fc }

  condition:
    any of them
}