rule TTP_XOR_MULT_DOSStub_ebd7 {
  strings:
    $key_ebd7 = { bf bf [2] cb a7 [2] 8c a5 [2] cb b4 [2] 85 b8 [2] 89 b2 [2] 9e b9 [2] 85 f7 [2] b8 }

  condition:
    any of them
}