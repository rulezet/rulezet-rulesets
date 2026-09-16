rule TTP_XOR_MULT_DOSStub_1bc8 {
  strings:
    $key_1bc8 = { 4f a0 [2] 3b b8 [2] 7c ba [2] 3b ab [2] 75 a7 [2] 79 ad [2] 6e a6 [2] 75 e8 [2] 48 }

  condition:
    any of them
}