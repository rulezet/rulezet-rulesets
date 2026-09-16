rule TTP_XOR_MULT_DOSStub_bdc4 {
  strings:
    $key_bdc4 = { e9 ac [2] 9d b4 [2] da b6 [2] 9d a7 [2] d3 ab [2] df a1 [2] c8 aa [2] d3 e4 [2] ee }

  condition:
    any of them
}