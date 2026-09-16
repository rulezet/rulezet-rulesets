rule TTP_XOR_MULT_DOSStub_7342 {
  strings:
    $key_7342 = { 27 2a [2] 53 32 [2] 14 30 [2] 53 21 [2] 1d 2d [2] 11 27 [2] 06 2c [2] 1d 62 [2] 20 }

  condition:
    any of them
}