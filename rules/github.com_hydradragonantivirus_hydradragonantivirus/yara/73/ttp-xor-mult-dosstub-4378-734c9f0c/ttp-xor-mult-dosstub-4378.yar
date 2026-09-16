rule TTP_XOR_MULT_DOSStub_4378 {
  strings:
    $key_4378 = { 17 10 [2] 63 08 [2] 24 0a [2] 63 1b [2] 2d 17 [2] 21 1d [2] 36 16 [2] 2d 58 [2] 10 }

  condition:
    any of them
}