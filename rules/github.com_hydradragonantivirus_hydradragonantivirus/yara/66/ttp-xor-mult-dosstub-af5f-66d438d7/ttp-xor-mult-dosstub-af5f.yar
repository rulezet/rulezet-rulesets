rule TTP_XOR_MULT_DOSStub_af5f {
  strings:
    $key_af5f = { fb 37 [2] 8f 2f [2] c8 2d [2] 8f 3c [2] c1 30 [2] cd 3a [2] da 31 [2] c1 7f [2] fc }

  condition:
    any of them
}