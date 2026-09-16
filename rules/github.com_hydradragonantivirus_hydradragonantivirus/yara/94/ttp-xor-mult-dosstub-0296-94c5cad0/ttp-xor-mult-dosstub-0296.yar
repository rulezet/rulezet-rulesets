rule TTP_XOR_MULT_DOSStub_0296 {
  strings:
    $key_0296 = { 56 fe [2] 22 e6 [2] 65 e4 [2] 22 f5 [2] 6c f9 [2] 60 f3 [2] 77 f8 [2] 6c b6 [2] 51 }

  condition:
    any of them
}