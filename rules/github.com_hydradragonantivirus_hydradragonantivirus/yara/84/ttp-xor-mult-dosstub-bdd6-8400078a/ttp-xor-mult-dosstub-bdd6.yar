rule TTP_XOR_MULT_DOSStub_bdd6 {
  strings:
    $key_bdd6 = { e9 be [2] 9d a6 [2] da a4 [2] 9d b5 [2] d3 b9 [2] df b3 [2] c8 b8 [2] d3 f6 [2] ee }

  condition:
    any of them
}