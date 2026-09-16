rule TTP_XOR_MULT_DOSStub_ac92 {
  strings:
    $key_ac92 = { f8 fa [2] 8c e2 [2] cb e0 [2] 8c f1 [2] c2 fd [2] ce f7 [2] d9 fc [2] c2 b2 [2] ff }

  condition:
    any of them
}