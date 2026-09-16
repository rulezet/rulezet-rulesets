rule TTP_XOR_MULT_DOSStub_bdad {
  strings:
    $key_bdad = { e9 c5 [2] 9d dd [2] da df [2] 9d ce [2] d3 c2 [2] df c8 [2] c8 c3 [2] d3 8d [2] ee }

  condition:
    any of them
}