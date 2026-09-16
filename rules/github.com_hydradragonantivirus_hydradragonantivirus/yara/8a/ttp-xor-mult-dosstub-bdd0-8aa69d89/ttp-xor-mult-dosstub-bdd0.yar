rule TTP_XOR_MULT_DOSStub_bdd0 {
  strings:
    $key_bdd0 = { e9 b8 [2] 9d a0 [2] da a2 [2] 9d b3 [2] d3 bf [2] df b5 [2] c8 be [2] d3 f0 [2] ee }

  condition:
    any of them
}