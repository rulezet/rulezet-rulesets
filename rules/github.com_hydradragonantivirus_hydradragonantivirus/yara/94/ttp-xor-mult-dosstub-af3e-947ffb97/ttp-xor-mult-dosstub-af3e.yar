rule TTP_XOR_MULT_DOSStub_af3e {
  strings:
    $key_af3e = { fb 56 [2] 8f 4e [2] c8 4c [2] 8f 5d [2] c1 51 [2] cd 5b [2] da 50 [2] c1 1e [2] fc }

  condition:
    any of them
}