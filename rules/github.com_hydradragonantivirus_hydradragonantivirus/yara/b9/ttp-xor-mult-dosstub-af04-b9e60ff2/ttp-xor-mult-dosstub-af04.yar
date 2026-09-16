rule TTP_XOR_MULT_DOSStub_af04 {
  strings:
    $key_af04 = { fb 6c [2] 8f 74 [2] c8 76 [2] 8f 67 [2] c1 6b [2] cd 61 [2] da 6a [2] c1 24 [2] fc }

  condition:
    any of them
}