rule TTP_XOR_MULT_DOSStub_4349 {
  strings:
    $key_4349 = { 17 21 [2] 63 39 [2] 24 3b [2] 63 2a [2] 2d 26 [2] 21 2c [2] 36 27 [2] 2d 69 [2] 10 }

  condition:
    any of them
}