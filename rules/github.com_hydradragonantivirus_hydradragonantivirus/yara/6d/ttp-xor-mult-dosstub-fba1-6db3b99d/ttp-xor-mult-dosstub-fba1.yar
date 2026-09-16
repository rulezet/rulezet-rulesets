rule TTP_XOR_MULT_DOSStub_fba1 {
  strings:
    $key_fba1 = { af c9 [2] db d1 [2] 9c d3 [2] db c2 [2] 95 ce [2] 99 c4 [2] 8e cf [2] 95 81 [2] a8 }

  condition:
    any of them
}