rule TTP_XOR_MULT_DOSStub_6cc5 {
  strings:
    $key_6cc5 = { 38 ad [2] 4c b5 [2] 0b b7 [2] 4c a6 [2] 02 aa [2] 0e a0 [2] 19 ab [2] 02 e5 [2] 3f }

  condition:
    any of them
}