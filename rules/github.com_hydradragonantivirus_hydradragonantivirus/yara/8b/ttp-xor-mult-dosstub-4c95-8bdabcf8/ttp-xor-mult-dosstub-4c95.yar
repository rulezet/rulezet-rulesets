rule TTP_XOR_MULT_DOSStub_4c95 {
  strings:
    $key_4c95 = { 18 fd [2] 6c e5 [2] 2b e7 [2] 6c f6 [2] 22 fa [2] 2e f0 [2] 39 fb [2] 22 b5 [2] 1f }

  condition:
    any of them
}