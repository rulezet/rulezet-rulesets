rule TTP_XOR_MULT_DOSStub_ebc6 {
  strings:
    $key_ebc6 = { bf ae [2] cb b6 [2] 8c b4 [2] cb a5 [2] 85 a9 [2] 89 a3 [2] 9e a8 [2] 85 e6 [2] b8 }

  condition:
    any of them
}