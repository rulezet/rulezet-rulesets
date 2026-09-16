rule TTP_XOR_MULT_DOSStub_af24 {
  strings:
    $key_af24 = { fb 4c [2] 8f 54 [2] c8 56 [2] 8f 47 [2] c1 4b [2] cd 41 [2] da 4a [2] c1 04 [2] fc }

  condition:
    any of them
}