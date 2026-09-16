rule TTP_XOR_MULT_DOSStub_bda6 {
  strings:
    $key_bda6 = { e9 ce [2] 9d d6 [2] da d4 [2] 9d c5 [2] d3 c9 [2] df c3 [2] c8 c8 [2] d3 86 [2] ee }

  condition:
    any of them
}