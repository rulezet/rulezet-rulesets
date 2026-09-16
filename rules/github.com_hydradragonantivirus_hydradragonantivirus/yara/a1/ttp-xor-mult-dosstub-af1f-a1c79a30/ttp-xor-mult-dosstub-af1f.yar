rule TTP_XOR_MULT_DOSStub_af1f {
  strings:
    $key_af1f = { fb 77 [2] 8f 6f [2] c8 6d [2] 8f 7c [2] c1 70 [2] cd 7a [2] da 71 [2] c1 3f [2] fc }

  condition:
    any of them
}