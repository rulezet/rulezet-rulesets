rule TTP_XOR_MULT_DOSStub_af28 {
  strings:
    $key_af28 = { fb 40 [2] 8f 58 [2] c8 5a [2] 8f 4b [2] c1 47 [2] cd 4d [2] da 46 [2] c1 08 [2] fc }

  condition:
    any of them
}