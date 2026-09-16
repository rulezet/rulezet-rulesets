rule TTP_XOR_MULT_DOSStub_4a90 {
  strings:
    $key_4a90 = { 1e f8 [2] 6a e0 [2] 2d e2 [2] 6a f3 [2] 24 ff [2] 28 f5 [2] 3f fe [2] 24 b0 [2] 19 }

  condition:
    any of them
}