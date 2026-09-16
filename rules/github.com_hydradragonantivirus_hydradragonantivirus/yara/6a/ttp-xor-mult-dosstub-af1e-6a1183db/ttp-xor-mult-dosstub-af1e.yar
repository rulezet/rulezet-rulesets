rule TTP_XOR_MULT_DOSStub_af1e {
  strings:
    $key_af1e = { fb 76 [2] 8f 6e [2] c8 6c [2] 8f 7d [2] c1 71 [2] cd 7b [2] da 70 [2] c1 3e [2] fc }

  condition:
    any of them
}