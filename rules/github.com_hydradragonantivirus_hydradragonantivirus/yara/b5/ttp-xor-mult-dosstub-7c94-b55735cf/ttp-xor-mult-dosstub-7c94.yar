rule TTP_XOR_MULT_DOSStub_7c94 {
  strings:
    $key_7c94 = { 28 fc [2] 5c e4 [2] 1b e6 [2] 5c f7 [2] 12 fb [2] 1e f1 [2] 09 fa [2] 12 b4 [2] 2f }

  condition:
    any of them
}