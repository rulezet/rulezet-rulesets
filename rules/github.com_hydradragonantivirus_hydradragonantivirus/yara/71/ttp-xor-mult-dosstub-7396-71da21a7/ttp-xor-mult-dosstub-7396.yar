rule TTP_XOR_MULT_DOSStub_7396 {
  strings:
    $key_7396 = { 27 fe [2] 53 e6 [2] 14 e4 [2] 53 f5 [2] 1d f9 [2] 11 f3 [2] 06 f8 [2] 1d b6 [2] 20 }

  condition:
    any of them
}