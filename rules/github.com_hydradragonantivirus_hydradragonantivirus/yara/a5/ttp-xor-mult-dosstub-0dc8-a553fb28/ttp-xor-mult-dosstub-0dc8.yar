rule TTP_XOR_MULT_DOSStub_0dc8 {
  strings:
    $key_0dc8 = { 59 a0 [2] 2d b8 [2] 6a ba [2] 2d ab [2] 63 a7 [2] 6f ad [2] 78 a6 [2] 63 e8 [2] 5e }

  condition:
    any of them
}