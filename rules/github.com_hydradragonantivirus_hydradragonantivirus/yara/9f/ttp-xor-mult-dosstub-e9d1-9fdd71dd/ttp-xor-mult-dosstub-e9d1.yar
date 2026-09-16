rule TTP_XOR_MULT_DOSStub_e9d1 {
  strings:
    $key_e9d1 = { bd b9 [2] c9 a1 [2] 8e a3 [2] c9 b2 [2] 87 be [2] 8b b4 [2] 9c bf [2] 87 f1 [2] ba }

  condition:
    any of them
}