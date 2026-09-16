rule TTP_XOR_MULT_DOSStub_bd96 {
  strings:
    $key_bd96 = { e9 fe [2] 9d e6 [2] da e4 [2] 9d f5 [2] d3 f9 [2] df f3 [2] c8 f8 [2] d3 b6 [2] ee }

  condition:
    any of them
}