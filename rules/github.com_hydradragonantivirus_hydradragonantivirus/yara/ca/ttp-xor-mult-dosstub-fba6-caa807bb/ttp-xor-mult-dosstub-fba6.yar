rule TTP_XOR_MULT_DOSStub_fba6 {
  strings:
    $key_fba6 = { af ce [2] db d6 [2] 9c d4 [2] db c5 [2] 95 c9 [2] 99 c3 [2] 8e c8 [2] 95 86 [2] a8 }

  condition:
    any of them
}