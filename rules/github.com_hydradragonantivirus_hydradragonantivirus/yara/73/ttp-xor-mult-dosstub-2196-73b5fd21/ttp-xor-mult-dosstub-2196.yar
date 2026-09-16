rule TTP_XOR_MULT_DOSStub_2196 {
  strings:
    $key_2196 = { 75 fe [2] 01 e6 [2] 46 e4 [2] 01 f5 [2] 4f f9 [2] 43 f3 [2] 54 f8 [2] 4f b6 [2] 72 }

  condition:
    any of them
}