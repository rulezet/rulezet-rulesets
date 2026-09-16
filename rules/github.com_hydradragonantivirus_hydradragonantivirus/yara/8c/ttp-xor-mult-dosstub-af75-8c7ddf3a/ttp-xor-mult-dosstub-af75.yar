rule TTP_XOR_MULT_DOSStub_af75 {
  strings:
    $key_af75 = { fb 1d [2] 8f 05 [2] c8 07 [2] 8f 16 [2] c1 1a [2] cd 10 [2] da 1b [2] c1 55 [2] fc }

  condition:
    any of them
}