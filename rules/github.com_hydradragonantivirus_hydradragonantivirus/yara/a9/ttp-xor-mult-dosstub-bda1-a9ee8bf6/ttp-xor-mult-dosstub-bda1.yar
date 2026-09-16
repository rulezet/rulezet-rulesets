rule TTP_XOR_MULT_DOSStub_bda1 {
  strings:
    $key_bda1 = { e9 c9 [2] 9d d1 [2] da d3 [2] 9d c2 [2] d3 ce [2] df c4 [2] c8 cf [2] d3 81 [2] ee }

  condition:
    any of them
}