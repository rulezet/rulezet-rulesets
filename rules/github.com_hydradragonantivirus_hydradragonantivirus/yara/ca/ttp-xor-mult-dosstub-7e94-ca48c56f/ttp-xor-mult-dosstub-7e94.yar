rule TTP_XOR_MULT_DOSStub_7e94 {
  strings:
    $key_7e94 = { 2a fc [2] 5e e4 [2] 19 e6 [2] 5e f7 [2] 10 fb [2] 1c f1 [2] 0b fa [2] 10 b4 [2] 2d }

  condition:
    any of them
}