rule TTP_XOR_MULT_DOSStub_3c95 {
  strings:
    $key_3c95 = { 68 fd [2] 1c e5 [2] 5b e7 [2] 1c f6 [2] 52 fa [2] 5e f0 [2] 49 fb [2] 52 b5 [2] 6f }

  condition:
    any of them
}