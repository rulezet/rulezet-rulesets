rule TTP_XOR_MULT_DOSStub_bd93 {
  strings:
    $key_bd93 = { e9 fb [2] 9d e3 [2] da e1 [2] 9d f0 [2] d3 fc [2] df f6 [2] c8 fd [2] d3 b3 [2] ee }

  condition:
    any of them
}