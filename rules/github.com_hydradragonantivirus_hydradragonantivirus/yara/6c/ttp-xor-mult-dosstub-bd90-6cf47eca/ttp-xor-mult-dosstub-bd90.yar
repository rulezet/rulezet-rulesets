rule TTP_XOR_MULT_DOSStub_bd90 {
  strings:
    $key_bd90 = { e9 f8 [2] 9d e0 [2] da e2 [2] 9d f3 [2] d3 ff [2] df f5 [2] c8 fe [2] d3 b0 [2] ee }

  condition:
    any of them
}