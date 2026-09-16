rule TTP_XOR_MULT_DOSStub_5242 {
  strings:
    $key_5242 = { 06 2a [2] 72 32 [2] 35 30 [2] 72 21 [2] 3c 2d [2] 30 27 [2] 27 2c [2] 3c 62 [2] 01 }

  condition:
    any of them
}