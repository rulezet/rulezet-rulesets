rule TTP_XOR_MULT_DOSStub_bdd4 {
  strings:
    $key_bdd4 = { e9 bc [2] 9d a4 [2] da a6 [2] 9d b7 [2] d3 bb [2] df b1 [2] c8 ba [2] d3 f4 [2] ee }

  condition:
    any of them
}