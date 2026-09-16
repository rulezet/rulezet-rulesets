rule TTP_XOR_MULT_DOSStub_2396 {
  strings:
    $key_2396 = { 77 fe [2] 03 e6 [2] 44 e4 [2] 03 f5 [2] 4d f9 [2] 41 f3 [2] 56 f8 [2] 4d b6 [2] 70 }

  condition:
    any of them
}