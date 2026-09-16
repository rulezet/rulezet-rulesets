rule TTP_XOR_MULT_DOSStub_af0c {
  strings:
    $key_af0c = { fb 64 [2] 8f 7c [2] c8 7e [2] 8f 6f [2] c1 63 [2] cd 69 [2] da 62 [2] c1 2c [2] fc }

  condition:
    any of them
}