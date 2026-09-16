rule TTP_XOR_MULT_DOSStub_bdd8 {
  strings:
    $key_bdd8 = { e9 b0 [2] 9d a8 [2] da aa [2] 9d bb [2] d3 b7 [2] df bd [2] c8 b6 [2] d3 f8 [2] ee }

  condition:
    any of them
}