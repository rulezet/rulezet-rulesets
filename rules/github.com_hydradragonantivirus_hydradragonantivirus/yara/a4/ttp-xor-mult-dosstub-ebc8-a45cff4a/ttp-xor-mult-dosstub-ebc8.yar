rule TTP_XOR_MULT_DOSStub_ebc8 {
  strings:
    $key_ebc8 = { bf a0 [2] cb b8 [2] 8c ba [2] cb ab [2] 85 a7 [2] 89 ad [2] 9e a6 [2] 85 e8 [2] b8 }

  condition:
    any of them
}