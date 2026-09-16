rule TTP_XOR_MULT_DOSStub_bdc7 {
  strings:
    $key_bdc7 = { e9 af [2] 9d b7 [2] da b5 [2] 9d a4 [2] d3 a8 [2] df a2 [2] c8 a9 [2] d3 e7 [2] ee }

  condition:
    any of them
}