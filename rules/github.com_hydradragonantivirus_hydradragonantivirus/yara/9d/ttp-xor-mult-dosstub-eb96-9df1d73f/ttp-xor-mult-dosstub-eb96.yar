rule TTP_XOR_MULT_DOSStub_eb96 {
  strings:
    $key_eb96 = { bf fe [2] cb e6 [2] 8c e4 [2] cb f5 [2] 85 f9 [2] 89 f3 [2] 9e f8 [2] 85 b6 [2] b8 }

  condition:
    any of them
}