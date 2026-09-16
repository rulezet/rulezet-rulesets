rule TTP_XOR_MULT_DOSStub_af4f {
  strings:
    $key_af4f = { fb 27 [2] 8f 3f [2] c8 3d [2] 8f 2c [2] c1 20 [2] cd 2a [2] da 21 [2] c1 6f [2] fc }

  condition:
    any of them
}