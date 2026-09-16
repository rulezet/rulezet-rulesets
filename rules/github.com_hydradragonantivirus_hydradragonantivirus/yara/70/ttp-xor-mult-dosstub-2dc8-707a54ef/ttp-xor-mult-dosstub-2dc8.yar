rule TTP_XOR_MULT_DOSStub_2dc8 {
  strings:
    $key_2dc8 = { 79 a0 [2] 0d b8 [2] 4a ba [2] 0d ab [2] 43 a7 [2] 4f ad [2] 58 a6 [2] 43 e8 [2] 7e }

  condition:
    any of them
}