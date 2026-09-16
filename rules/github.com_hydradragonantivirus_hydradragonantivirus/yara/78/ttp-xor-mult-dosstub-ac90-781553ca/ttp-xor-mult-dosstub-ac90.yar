rule TTP_XOR_MULT_DOSStub_ac90 {
  strings:
    $key_ac90 = { f8 f8 [2] 8c e0 [2] cb e2 [2] 8c f3 [2] c2 ff [2] ce f5 [2] d9 fe [2] c2 b0 [2] ff }

  condition:
    any of them
}