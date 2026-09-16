rule TTP_XOR_MULT_DOSStub_bdb4 {
  strings:
    $key_bdb4 = { e9 dc [2] 9d c4 [2] da c6 [2] 9d d7 [2] d3 db [2] df d1 [2] c8 da [2] d3 94 [2] ee }

  condition:
    any of them
}