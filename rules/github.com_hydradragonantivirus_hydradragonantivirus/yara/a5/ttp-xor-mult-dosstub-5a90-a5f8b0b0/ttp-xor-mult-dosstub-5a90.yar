rule TTP_XOR_MULT_DOSStub_5a90 {
  strings:
    $key_5a90 = { 0e f8 [2] 7a e0 [2] 3d e2 [2] 7a f3 [2] 34 ff [2] 38 f5 [2] 2f fe [2] 34 b0 [2] 09 }

  condition:
    any of them
}