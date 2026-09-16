rule TTP_XOR_MULT_DOSStub_3396 {
  strings:
    $key_3396 = { 67 fe [2] 13 e6 [2] 54 e4 [2] 13 f5 [2] 5d f9 [2] 51 f3 [2] 46 f8 [2] 5d b6 [2] 60 }

  condition:
    any of them
}