rule TTP_XOR_MULT_DOSStub_3894 {
  strings:
    $key_3894 = { 6c fc [2] 18 e4 [2] 5f e6 [2] 18 f7 [2] 56 fb [2] 5a f1 [2] 4d fa [2] 56 b4 [2] 6b }

  condition:
    any of them
}