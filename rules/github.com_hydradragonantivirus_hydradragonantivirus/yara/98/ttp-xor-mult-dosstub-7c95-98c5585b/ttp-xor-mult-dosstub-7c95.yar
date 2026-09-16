rule TTP_XOR_MULT_DOSStub_7c95 {
  strings:
    $key_7c95 = { 28 fd [2] 5c e5 [2] 1b e7 [2] 5c f6 [2] 12 fa [2] 1e f0 [2] 09 fb [2] 12 b5 [2] 2f }

  condition:
    any of them
}