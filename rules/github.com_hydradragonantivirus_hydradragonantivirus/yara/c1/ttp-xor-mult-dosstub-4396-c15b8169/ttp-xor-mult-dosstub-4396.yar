rule TTP_XOR_MULT_DOSStub_4396 {
  strings:
    $key_4396 = { 17 fe [2] 63 e6 [2] 24 e4 [2] 63 f5 [2] 2d f9 [2] 21 f3 [2] 36 f8 [2] 2d b6 [2] 10 }

  condition:
    any of them
}