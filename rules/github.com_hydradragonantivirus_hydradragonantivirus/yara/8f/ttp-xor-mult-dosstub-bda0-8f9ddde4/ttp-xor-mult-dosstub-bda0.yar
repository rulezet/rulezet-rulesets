rule TTP_XOR_MULT_DOSStub_bda0 {
  strings:
    $key_bda0 = { e9 c8 [2] 9d d0 [2] da d2 [2] 9d c3 [2] d3 cf [2] df c5 [2] c8 ce [2] d3 80 [2] ee }

  condition:
    any of them
}