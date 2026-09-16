rule TTP_XOR_MULT_DOSStub_afa9 {
  strings:
    $key_afa9 = { fb c1 [2] 8f d9 [2] c8 db [2] 8f ca [2] c1 c6 [2] cd cc [2] da c7 [2] c1 89 [2] fc }

  condition:
    any of them
}