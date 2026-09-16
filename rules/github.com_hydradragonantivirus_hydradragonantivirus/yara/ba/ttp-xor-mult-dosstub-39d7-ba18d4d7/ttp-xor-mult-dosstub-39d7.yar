rule TTP_XOR_MULT_DOSStub_39d7 {
  strings:
    $key_39d7 = { 6d bf [2] 19 a7 [2] 5e a5 [2] 19 b4 [2] 57 b8 [2] 5b b2 [2] 4c b9 [2] 57 f7 [2] 6a }

  condition:
    any of them
}