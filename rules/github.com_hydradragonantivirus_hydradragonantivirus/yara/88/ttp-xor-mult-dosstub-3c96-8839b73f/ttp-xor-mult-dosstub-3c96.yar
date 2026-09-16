rule TTP_XOR_MULT_DOSStub_3c96 {
  strings:
    $key_3c96 = { 68 fe [2] 1c e6 [2] 5b e4 [2] 1c f5 [2] 52 f9 [2] 5e f3 [2] 49 f8 [2] 52 b6 [2] 6f }

  condition:
    any of them
}