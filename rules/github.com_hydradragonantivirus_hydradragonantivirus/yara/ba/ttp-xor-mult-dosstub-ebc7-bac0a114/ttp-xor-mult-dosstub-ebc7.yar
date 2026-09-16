rule TTP_XOR_MULT_DOSStub_ebc7 {
  strings:
    $key_ebc7 = { bf af [2] cb b7 [2] 8c b5 [2] cb a4 [2] 85 a8 [2] 89 a2 [2] 9e a9 [2] 85 e7 [2] b8 }

  condition:
    any of them
}