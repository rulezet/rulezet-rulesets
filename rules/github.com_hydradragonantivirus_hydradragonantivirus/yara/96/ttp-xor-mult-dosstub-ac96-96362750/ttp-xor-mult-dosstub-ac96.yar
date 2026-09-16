rule TTP_XOR_MULT_DOSStub_ac96 {
  strings:
    $key_ac96 = { f8 fe [2] 8c e6 [2] cb e4 [2] 8c f5 [2] c2 f9 [2] ce f3 [2] d9 f8 [2] c2 b6 [2] ff }

  condition:
    any of them
}