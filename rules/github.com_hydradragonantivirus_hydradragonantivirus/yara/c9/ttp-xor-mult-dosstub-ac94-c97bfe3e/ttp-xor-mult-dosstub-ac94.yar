rule TTP_XOR_MULT_DOSStub_ac94 {
  strings:
    $key_ac94 = { f8 fc [2] 8c e4 [2] cb e6 [2] 8c f7 [2] c2 fb [2] ce f1 [2] d9 fa [2] c2 b4 [2] ff }

  condition:
    any of them
}