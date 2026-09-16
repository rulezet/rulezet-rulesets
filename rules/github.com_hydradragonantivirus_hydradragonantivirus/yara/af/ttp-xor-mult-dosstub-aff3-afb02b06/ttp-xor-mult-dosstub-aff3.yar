rule TTP_XOR_MULT_DOSStub_aff3 {
  strings:
    $key_aff3 = { fb 9b [2] 8f 83 [2] c8 81 [2] 8f 90 [2] c1 9c [2] cd 96 [2] da 9d [2] c1 d3 [2] fc }

  condition:
    any of them
}