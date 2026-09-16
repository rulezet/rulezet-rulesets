rule TTP_XOR_MULT_DOSStub_1a94 {
  strings:
    $key_1a94 = { 4e fc [2] 3a e4 [2] 7d e6 [2] 3a f7 [2] 74 fb [2] 78 f1 [2] 6f fa [2] 74 b4 [2] 49 }

  condition:
    any of them
}