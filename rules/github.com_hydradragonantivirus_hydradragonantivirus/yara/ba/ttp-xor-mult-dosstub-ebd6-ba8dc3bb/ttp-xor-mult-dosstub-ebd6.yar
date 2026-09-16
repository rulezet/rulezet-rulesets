rule TTP_XOR_MULT_DOSStub_ebd6 {
  strings:
    $key_ebd6 = { bf be [2] cb a6 [2] 8c a4 [2] cb b5 [2] 85 b9 [2] 89 b3 [2] 9e b8 [2] 85 f6 [2] b8 }

  condition:
    any of them
}