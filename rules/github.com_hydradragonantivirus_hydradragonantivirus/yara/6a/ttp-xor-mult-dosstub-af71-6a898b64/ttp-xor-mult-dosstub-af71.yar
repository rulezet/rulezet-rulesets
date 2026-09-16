rule TTP_XOR_MULT_DOSStub_af71 {
  strings:
    $key_af71 = { fb 19 [2] 8f 01 [2] c8 03 [2] 8f 12 [2] c1 1e [2] cd 14 [2] da 1f [2] c1 51 [2] fc }

  condition:
    any of them
}