rule TTP_XOR_MULT_DOSStub_2296 {
  strings:
    $key_2296 = { 76 fe [2] 02 e6 [2] 45 e4 [2] 02 f5 [2] 4c f9 [2] 40 f3 [2] 57 f8 [2] 4c b6 [2] 71 }

  condition:
    any of them
}