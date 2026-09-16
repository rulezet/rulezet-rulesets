rule TTP_XOR_MULT_DOSStub_7196 {
  strings:
    $key_7196 = { 25 fe [2] 51 e6 [2] 16 e4 [2] 51 f5 [2] 1f f9 [2] 13 f3 [2] 04 f8 [2] 1f b6 [2] 22 }

  condition:
    any of them
}