rule TTP_XOR_MULT_DOSStub_fba7 {
  strings:
    $key_fba7 = { af cf [2] db d7 [2] 9c d5 [2] db c4 [2] 95 c8 [2] 99 c2 [2] 8e c9 [2] 95 87 [2] a8 }

  condition:
    any of them
}