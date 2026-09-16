rule TTP_XOR_MULT_DOSStub_1dc8 {
  strings:
    $key_1dc8 = { 49 a0 [2] 3d b8 [2] 7a ba [2] 3d ab [2] 73 a7 [2] 7f ad [2] 68 a6 [2] 73 e8 [2] 4e }

  condition:
    any of them
}