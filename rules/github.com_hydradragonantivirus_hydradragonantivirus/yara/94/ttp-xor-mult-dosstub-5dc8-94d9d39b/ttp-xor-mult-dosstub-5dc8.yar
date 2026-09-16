rule TTP_XOR_MULT_DOSStub_5dc8 {
  strings:
    $key_5dc8 = { 09 a0 [2] 7d b8 [2] 3a ba [2] 7d ab [2] 33 a7 [2] 3f ad [2] 28 a6 [2] 33 e8 [2] 0e }

  condition:
    any of them
}