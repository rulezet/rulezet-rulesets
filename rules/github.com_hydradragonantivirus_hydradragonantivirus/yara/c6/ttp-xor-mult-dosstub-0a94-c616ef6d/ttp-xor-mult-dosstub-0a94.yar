rule TTP_XOR_MULT_DOSStub_0a94 {
  strings:
    $key_0a94 = { 5e fc [2] 2a e4 [2] 6d e6 [2] 2a f7 [2] 64 fb [2] 68 f1 [2] 7f fa [2] 64 b4 [2] 59 }

  condition:
    any of them
}