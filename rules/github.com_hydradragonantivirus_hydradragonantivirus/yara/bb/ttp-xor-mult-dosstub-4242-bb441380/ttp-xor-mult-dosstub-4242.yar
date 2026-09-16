rule TTP_XOR_MULT_DOSStub_4242 {
  strings:
    $key_4242 = { 16 2a [2] 62 32 [2] 25 30 [2] 62 21 [2] 2c 2d [2] 20 27 [2] 37 2c [2] 2c 62 [2] 11 }

  condition:
    any of them
}