rule TTP_XOR_MULT_DOSStub_af2b {
  strings:
    $key_af2b = { fb 43 [2] 8f 5b [2] c8 59 [2] 8f 48 [2] c1 44 [2] cd 4e [2] da 45 [2] c1 0b [2] fc }

  condition:
    any of them
}