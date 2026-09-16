rule TTP_XOR_MULT_DOSStub_4372 {
  strings:
    $key_4372 = { 17 1a [2] 63 02 [2] 24 00 [2] 63 11 [2] 2d 1d [2] 21 17 [2] 36 1c [2] 2d 52 [2] 10 }

  condition:
    any of them
}