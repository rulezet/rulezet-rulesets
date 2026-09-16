rule TTP_XOR_MULT_DOSStub_2c94 {
  strings:
    $key_2c94 = { 78 fc [2] 0c e4 [2] 4b e6 [2] 0c f7 [2] 42 fb [2] 4e f1 [2] 59 fa [2] 42 b4 [2] 7f }

  condition:
    any of them
}