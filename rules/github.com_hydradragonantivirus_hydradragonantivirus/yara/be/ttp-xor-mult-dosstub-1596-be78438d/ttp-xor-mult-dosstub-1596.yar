rule TTP_XOR_MULT_DOSStub_1596 {
  strings:
    $key_1596 = { 41 fe [2] 35 e6 [2] 72 e4 [2] 35 f5 [2] 7b f9 [2] 77 f3 [2] 60 f8 [2] 7b b6 [2] 46 }

  condition:
    any of them
}