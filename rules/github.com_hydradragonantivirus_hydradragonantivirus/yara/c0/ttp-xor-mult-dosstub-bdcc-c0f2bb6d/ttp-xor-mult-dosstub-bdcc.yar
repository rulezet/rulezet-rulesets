rule TTP_XOR_MULT_DOSStub_bdcc {
  strings:
    $key_bdcc = { e9 a4 [2] 9d bc [2] da be [2] 9d af [2] d3 a3 [2] df a9 [2] c8 a2 [2] d3 ec [2] ee }

  condition:
    any of them
}