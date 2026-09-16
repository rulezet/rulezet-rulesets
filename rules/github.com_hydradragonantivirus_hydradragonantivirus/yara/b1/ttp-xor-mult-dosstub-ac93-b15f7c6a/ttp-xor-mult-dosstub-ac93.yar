rule TTP_XOR_MULT_DOSStub_ac93 {
  strings:
    $key_ac93 = { f8 fb [2] 8c e3 [2] cb e1 [2] 8c f0 [2] c2 fc [2] ce f6 [2] d9 fd [2] c2 b3 [2] ff }

  condition:
    any of them
}