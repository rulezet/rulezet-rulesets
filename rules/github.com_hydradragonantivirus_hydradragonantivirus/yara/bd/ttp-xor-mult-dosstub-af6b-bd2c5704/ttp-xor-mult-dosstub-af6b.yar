rule TTP_XOR_MULT_DOSStub_af6b {
  strings:
    $key_af6b = { fb 03 [2] 8f 1b [2] c8 19 [2] 8f 08 [2] c1 04 [2] cd 0e [2] da 05 [2] c1 4b [2] fc }

  condition:
    any of them
}