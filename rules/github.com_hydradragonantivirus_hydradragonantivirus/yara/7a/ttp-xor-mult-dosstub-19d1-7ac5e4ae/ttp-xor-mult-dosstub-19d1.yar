rule TTP_XOR_MULT_DOSStub_19d1 {
  strings:
    $key_19d1 = { 4d b9 [2] 39 a1 [2] 7e a3 [2] 39 b2 [2] 77 be [2] 7b b4 [2] 6c bf [2] 77 f1 [2] 4a }

  condition:
    any of them
}