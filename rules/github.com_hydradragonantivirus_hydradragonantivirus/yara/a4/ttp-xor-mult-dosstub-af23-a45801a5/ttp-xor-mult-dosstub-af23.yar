rule TTP_XOR_MULT_DOSStub_af23 {
  strings:
    $key_af23 = { fb 4b [2] 8f 53 [2] c8 51 [2] 8f 40 [2] c1 4c [2] cd 46 [2] da 4d [2] c1 03 [2] fc }

  condition:
    any of them
}