rule TTP_XOR_MULT_DOSStub_bd89 {
  strings:
    $key_bd89 = { e9 e1 [2] 9d f9 [2] da fb [2] 9d ea [2] d3 e6 [2] df ec [2] c8 e7 [2] d3 a9 [2] ee }

  condition:
    any of them
}