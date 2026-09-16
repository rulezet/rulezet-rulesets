rule TTP_XOR_MULT_DOSStub_bd98 {
  strings:
    $key_bd98 = { e9 f0 [2] 9d e8 [2] da ea [2] 9d fb [2] d3 f7 [2] df fd [2] c8 f6 [2] d3 b8 [2] ee }

  condition:
    any of them
}