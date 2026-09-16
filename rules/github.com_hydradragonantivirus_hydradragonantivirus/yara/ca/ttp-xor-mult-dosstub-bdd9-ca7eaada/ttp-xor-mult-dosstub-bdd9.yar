rule TTP_XOR_MULT_DOSStub_bdd9 {
  strings:
    $key_bdd9 = { e9 b1 [2] 9d a9 [2] da ab [2] 9d ba [2] d3 b6 [2] df bc [2] c8 b7 [2] d3 f9 [2] ee }

  condition:
    any of them
}