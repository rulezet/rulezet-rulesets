rule TTP_XOR_MULT_DOSStub_af02 {
  strings:
    $key_af02 = { fb 6a [2] 8f 72 [2] c8 70 [2] 8f 61 [2] c1 6d [2] cd 67 [2] da 6c [2] c1 22 [2] fc }

  condition:
    any of them
}