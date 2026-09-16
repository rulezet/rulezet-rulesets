rule TTP_XOR_MULT_DOSStub_6c96 {
  strings:
    $key_6c96 = { 38 fe [2] 4c e6 [2] 0b e4 [2] 4c f5 [2] 02 f9 [2] 0e f3 [2] 19 f8 [2] 02 b6 [2] 3f }

  condition:
    any of them
}