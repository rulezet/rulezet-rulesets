rule TTP_XOR_MULT_DOSStub_4796 {
  strings:
    $key_4796 = { 13 fe [2] 67 e6 [2] 20 e4 [2] 67 f5 [2] 29 f9 [2] 25 f3 [2] 32 f8 [2] 29 b6 [2] 14 }

  condition:
    any of them
}