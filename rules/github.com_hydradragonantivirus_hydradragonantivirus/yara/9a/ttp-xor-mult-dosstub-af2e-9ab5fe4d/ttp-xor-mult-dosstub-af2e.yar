rule TTP_XOR_MULT_DOSStub_af2e {
  strings:
    $key_af2e = { fb 46 [2] 8f 5e [2] c8 5c [2] 8f 4d [2] c1 41 [2] cd 4b [2] da 40 [2] c1 0e [2] fc }

  condition:
    any of them
}