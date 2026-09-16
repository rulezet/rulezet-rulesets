rule TTP_XOR_MULT_DOSStub_af2c {
  strings:
    $key_af2c = { fb 44 [2] 8f 5c [2] c8 5e [2] 8f 4f [2] c1 43 [2] cd 49 [2] da 42 [2] c1 0c [2] fc }

  condition:
    any of them
}