rule TTP_XOR_MULT_DOSStub_0894 {
  strings:
    $key_0894 = { 5c fc [2] 28 e4 [2] 6f e6 [2] 28 f7 [2] 66 fb [2] 6a f1 [2] 7d fa [2] 66 b4 [2] 5b }

  condition:
    any of them
}