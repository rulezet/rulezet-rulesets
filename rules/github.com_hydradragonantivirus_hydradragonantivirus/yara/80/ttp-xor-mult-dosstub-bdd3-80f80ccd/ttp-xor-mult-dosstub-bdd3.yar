rule TTP_XOR_MULT_DOSStub_bdd3 {
  strings:
    $key_bdd3 = { e9 bb [2] 9d a3 [2] da a1 [2] 9d b0 [2] d3 bc [2] df b6 [2] c8 bd [2] d3 f3 [2] ee }

  condition:
    any of them
}