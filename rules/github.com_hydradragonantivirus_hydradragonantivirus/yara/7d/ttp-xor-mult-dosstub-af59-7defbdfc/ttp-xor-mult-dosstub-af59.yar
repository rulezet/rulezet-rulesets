rule TTP_XOR_MULT_DOSStub_af59 {
  strings:
    $key_af59 = { fb 31 [2] 8f 29 [2] c8 2b [2] 8f 3a [2] c1 36 [2] cd 3c [2] da 37 [2] c1 79 [2] fc }

  condition:
    any of them
}