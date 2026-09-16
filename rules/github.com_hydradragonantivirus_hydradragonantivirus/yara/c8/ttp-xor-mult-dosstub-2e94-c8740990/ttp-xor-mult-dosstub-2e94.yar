rule TTP_XOR_MULT_DOSStub_2e94 {
  strings:
    $key_2e94 = { 7a fc [2] 0e e4 [2] 49 e6 [2] 0e f7 [2] 40 fb [2] 4c f1 [2] 5b fa [2] 40 b4 [2] 7d }

  condition:
    any of them
}