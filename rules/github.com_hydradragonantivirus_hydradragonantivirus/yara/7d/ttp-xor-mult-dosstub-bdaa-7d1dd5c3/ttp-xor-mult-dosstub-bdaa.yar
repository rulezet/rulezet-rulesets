rule TTP_XOR_MULT_DOSStub_bdaa {
  strings:
    $key_bdaa = { e9 c2 [2] 9d da [2] da d8 [2] 9d c9 [2] d3 c5 [2] df cf [2] c8 c4 [2] d3 8a [2] ee }

  condition:
    any of them
}