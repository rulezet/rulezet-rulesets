rule TTP_XOR_MULT_DOSStub_5c97 {
  strings:
    $key_5c97 = { 08 ff [2] 7c e7 [2] 3b e5 [2] 7c f4 [2] 32 f8 [2] 3e f2 [2] 29 f9 [2] 32 b7 [2] 0f }

  condition:
    any of them
}