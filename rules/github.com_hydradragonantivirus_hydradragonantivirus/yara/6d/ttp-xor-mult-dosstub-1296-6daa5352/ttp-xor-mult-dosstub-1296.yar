rule TTP_XOR_MULT_DOSStub_1296 {
  strings:
    $key_1296 = { 46 fe [2] 32 e6 [2] 75 e4 [2] 32 f5 [2] 7c f9 [2] 70 f3 [2] 67 f8 [2] 7c b6 [2] 41 }

  condition:
    any of them
}