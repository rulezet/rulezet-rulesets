rule TTP_XOR_MULT_DOSStub_af11 {
  strings:
    $key_af11 = { fb 79 [2] 8f 61 [2] c8 63 [2] 8f 72 [2] c1 7e [2] cd 74 [2] da 7f [2] c1 31 [2] fc }

  condition:
    any of them
}