rule TTP_XOR_MULT_DOSStub_3a94 {
  strings:
    $key_3a94 = { 6e fc [2] 1a e4 [2] 5d e6 [2] 1a f7 [2] 54 fb [2] 58 f1 [2] 4f fa [2] 54 b4 [2] 69 }

  condition:
    any of them
}