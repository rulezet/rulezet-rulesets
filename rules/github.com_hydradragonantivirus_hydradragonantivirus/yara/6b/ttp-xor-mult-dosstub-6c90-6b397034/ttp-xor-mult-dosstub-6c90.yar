rule TTP_XOR_MULT_DOSStub_6c90 {
  strings:
    $key_6c90 = { 38 f8 [2] 4c e0 [2] 0b e2 [2] 4c f3 [2] 02 ff [2] 0e f5 [2] 19 fe [2] 02 b0 [2] 3f }

  condition:
    any of them
}