rule TTP_XOR_MULT_DOSStub_af6d {
  strings:
    $key_af6d = { fb 05 [2] 8f 1d [2] c8 1f [2] 8f 0e [2] c1 02 [2] cd 08 [2] da 03 [2] c1 4d [2] fc }

  condition:
    any of them
}