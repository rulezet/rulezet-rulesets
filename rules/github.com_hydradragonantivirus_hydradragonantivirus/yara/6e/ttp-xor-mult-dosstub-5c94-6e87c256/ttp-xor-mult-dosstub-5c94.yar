rule TTP_XOR_MULT_DOSStub_5c94 {
  strings:
    $key_5c94 = { 08 fc [2] 7c e4 [2] 3b e6 [2] 7c f7 [2] 32 fb [2] 3e f1 [2] 29 fa [2] 32 b4 [2] 0f }

  condition:
    any of them
}