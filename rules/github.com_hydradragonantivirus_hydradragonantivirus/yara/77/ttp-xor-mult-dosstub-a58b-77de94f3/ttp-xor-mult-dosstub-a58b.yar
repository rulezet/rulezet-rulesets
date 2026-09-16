rule TTP_XOR_MULT_DOSStub_a58b {
  strings:
    $key_a58b = { f1 e3 [2] 85 fb [2] c2 f9 [2] 85 e8 [2] cb e4 [2] c7 ee [2] d0 e5 [2] cb ab [2] f6 }

  condition:
    any of them
}