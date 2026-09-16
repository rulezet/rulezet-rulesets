rule TTP_XOR_MULT_DOSStub_bdb9 {
  strings:
    $key_bdb9 = { e9 d1 [2] 9d c9 [2] da cb [2] 9d da [2] d3 d6 [2] df dc [2] c8 d7 [2] d3 99 [2] ee }

  condition:
    any of them
}