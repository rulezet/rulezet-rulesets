rule TTP_XOR_MULT_DOSStub_ac84 {
  strings:
    $key_ac84 = { f8 ec [2] 8c f4 [2] cb f6 [2] 8c e7 [2] c2 eb [2] ce e1 [2] d9 ea [2] c2 a4 [2] ff }

  condition:
    any of them
}