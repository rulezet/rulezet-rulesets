rule TTP_XOR_MULT_DOSStub_ebc0 {
  strings:
    $key_ebc0 = { bf a8 [2] cb b0 [2] 8c b2 [2] cb a3 [2] 85 af [2] 89 a5 [2] 9e ae [2] 85 e0 [2] b8 }

  condition:
    any of them
}