rule TTP_XOR_MULT_DOSStub_0e94 {
  strings:
    $key_0e94 = { 5a fc [2] 2e e4 [2] 69 e6 [2] 2e f7 [2] 60 fb [2] 6c f1 [2] 7b fa [2] 60 b4 [2] 5d }

  condition:
    any of them
}