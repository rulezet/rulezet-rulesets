rule TTP_XOR_MULT_DOSStub_4890 {
  strings:
    $key_4890 = { 1c f8 [2] 68 e0 [2] 2f e2 [2] 68 f3 [2] 26 ff [2] 2a f5 [2] 3d fe [2] 26 b0 [2] 1b }

  condition:
    any of them
}