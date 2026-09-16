rule TTP_XOR_MULT_DOSStub_bd9a {
  strings:
    $key_bd9a = { e9 f2 [2] 9d ea [2] da e8 [2] 9d f9 [2] d3 f5 [2] df ff [2] c8 f4 [2] d3 ba [2] ee }

  condition:
    any of them
}