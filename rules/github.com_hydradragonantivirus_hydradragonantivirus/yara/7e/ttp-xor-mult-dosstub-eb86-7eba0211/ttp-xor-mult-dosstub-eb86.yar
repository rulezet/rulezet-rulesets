rule TTP_XOR_MULT_DOSStub_eb86 {
  strings:
    $key_eb86 = { bf ee [2] cb f6 [2] 8c f4 [2] cb e5 [2] 85 e9 [2] 89 e3 [2] 9e e8 [2] 85 a6 [2] b8 }

  condition:
    any of them
}