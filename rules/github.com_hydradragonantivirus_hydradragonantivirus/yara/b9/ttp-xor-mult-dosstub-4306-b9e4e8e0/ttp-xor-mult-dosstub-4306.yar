rule TTP_XOR_MULT_DOSStub_4306 {
  strings:
    $key_4306 = { 17 6e [2] 63 76 [2] 24 74 [2] 63 65 [2] 2d 69 [2] 21 63 [2] 36 68 [2] 2d 26 [2] 10 }

  condition:
    any of them
}