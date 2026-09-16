rule TTP_XOR_MULT_DOSStub_af1b {
  strings:
    $key_af1b = { fb 73 [2] 8f 6b [2] c8 69 [2] 8f 78 [2] c1 74 [2] cd 7e [2] da 75 [2] c1 3b [2] fc }

  condition:
    any of them
}