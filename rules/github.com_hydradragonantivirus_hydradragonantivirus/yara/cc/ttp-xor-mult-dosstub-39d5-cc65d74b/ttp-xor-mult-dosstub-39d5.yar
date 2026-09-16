rule TTP_XOR_MULT_DOSStub_39d5 {
  strings:
    $key_39d5 = { 6d bd [2] 19 a5 [2] 5e a7 [2] 19 b6 [2] 57 ba [2] 5b b0 [2] 4c bb [2] 57 f5 [2] 6a }

  condition:
    any of them
}