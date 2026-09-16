rule TTP_XOR_MULT_DOSStub_af2d {
  strings:
    $key_af2d = { fb 45 [2] 8f 5d [2] c8 5f [2] 8f 4e [2] c1 42 [2] cd 48 [2] da 43 [2] c1 0d [2] fc }

  condition:
    any of them
}