rule TTP_XOR_MULT_DOSStub_af5e {
  strings:
    $key_af5e = { fb 36 [2] 8f 2e [2] c8 2c [2] 8f 3d [2] c1 31 [2] cd 3b [2] da 30 [2] c1 7e [2] fc }

  condition:
    any of them
}