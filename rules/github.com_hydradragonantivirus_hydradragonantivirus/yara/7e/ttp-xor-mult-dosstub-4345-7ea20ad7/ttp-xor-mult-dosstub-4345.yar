rule TTP_XOR_MULT_DOSStub_4345 {
  strings:
    $key_4345 = { 17 2d [2] 63 35 [2] 24 37 [2] 63 26 [2] 2d 2a [2] 21 20 [2] 36 2b [2] 2d 65 [2] 10 }

  condition:
    any of them
}