rule TTP_XOR_MULT_DOSStub_af25 {
  strings:
    $key_af25 = { fb 4d [2] 8f 55 [2] c8 57 [2] 8f 46 [2] c1 4a [2] cd 40 [2] da 4b [2] c1 05 [2] fc }

  condition:
    any of them
}