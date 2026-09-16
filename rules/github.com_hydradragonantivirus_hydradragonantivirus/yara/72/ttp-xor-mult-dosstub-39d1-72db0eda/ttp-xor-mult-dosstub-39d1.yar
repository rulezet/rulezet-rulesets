rule TTP_XOR_MULT_DOSStub_39d1 {
  strings:
    $key_39d1 = { 6d b9 [2] 19 a1 [2] 5e a3 [2] 19 b2 [2] 57 be [2] 5b b4 [2] 4c bf [2] 57 f1 [2] 6a }

  condition:
    any of them
}