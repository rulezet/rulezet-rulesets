rule TTP_XOR_MULT_DOSStub_7c97 {
  strings:
    $key_7c97 = { 28 ff [2] 5c e7 [2] 1b e5 [2] 5c f4 [2] 12 f8 [2] 1e f2 [2] 09 f9 [2] 12 b7 [2] 2f }

  condition:
    any of them
}