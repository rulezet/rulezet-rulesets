rule TTP_XOR_MULT_DOSStub_eb81 {
  strings:
    $key_eb81 = { bf e9 [2] cb f1 [2] 8c f3 [2] cb e2 [2] 85 ee [2] 89 e4 [2] 9e ef [2] 85 a1 [2] b8 }

  condition:
    any of them
}