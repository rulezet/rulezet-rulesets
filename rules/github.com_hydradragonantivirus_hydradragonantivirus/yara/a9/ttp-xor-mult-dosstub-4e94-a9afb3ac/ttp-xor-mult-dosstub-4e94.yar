rule TTP_XOR_MULT_DOSStub_4e94 {
  strings:
    $key_4e94 = { 1a fc [2] 6e e4 [2] 29 e6 [2] 6e f7 [2] 20 fb [2] 2c f1 [2] 3b fa [2] 20 b4 [2] 1d }

  condition:
    any of them
}