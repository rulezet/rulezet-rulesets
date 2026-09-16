rule TTP_XOR_MULT_DOSStub_c894 {
  strings:
    $key_c894 = { 9c fc [2] e8 e4 [2] af e6 [2] e8 f7 [2] a6 fb [2] aa f1 [2] bd fa [2] a6 b4 [2] 9b }

  condition:
    any of them
}