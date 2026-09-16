rule TTP_XOR_MULT_DOSStub_4342 {
  strings:
    $key_4342 = { 17 2a [2] 63 32 [2] 24 30 [2] 63 21 [2] 2d 2d [2] 21 27 [2] 36 2c [2] 2d 62 [2] 10 }

  condition:
    any of them
}