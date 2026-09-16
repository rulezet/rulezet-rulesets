rule TTP_XOR_MULT_DOSStub_7dc8 {
  strings:
    $key_7dc8 = { 29 a0 [2] 5d b8 [2] 1a ba [2] 5d ab [2] 13 a7 [2] 1f ad [2] 08 a6 [2] 13 e8 [2] 2e }

  condition:
    any of them
}