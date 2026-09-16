rule TTP_XOR_MULT_DOSStub_3c90 {
  strings:
    $key_3c90 = { 68 f8 [2] 1c e0 [2] 5b e2 [2] 1c f3 [2] 52 ff [2] 5e f5 [2] 49 fe [2] 52 b0 [2] 6f }

  condition:
    any of them
}