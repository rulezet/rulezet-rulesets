rule TTP_XOR_MULT_DOSStub_4248 {
  strings:
    $key_4248 = { 16 20 [2] 62 38 [2] 25 3a [2] 62 2b [2] 2c 27 [2] 20 2d [2] 37 26 [2] 2c 68 [2] 11 }

  condition:
    any of them
}