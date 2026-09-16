rule TTP_XOR_MULT_DOSStub_4272 {
  strings:
    $key_4272 = { 16 1a [2] 62 02 [2] 25 00 [2] 62 11 [2] 2c 1d [2] 20 17 [2] 37 1c [2] 2c 52 [2] 11 }

  condition:
    any of them
}