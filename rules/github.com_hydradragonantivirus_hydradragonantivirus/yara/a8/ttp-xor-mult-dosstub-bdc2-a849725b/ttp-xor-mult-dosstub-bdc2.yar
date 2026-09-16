rule TTP_XOR_MULT_DOSStub_bdc2 {
  strings:
    $key_bdc2 = { e9 aa [2] 9d b2 [2] da b0 [2] 9d a1 [2] d3 ad [2] df a7 [2] c8 ac [2] d3 e2 [2] ee }

  condition:
    any of them
}