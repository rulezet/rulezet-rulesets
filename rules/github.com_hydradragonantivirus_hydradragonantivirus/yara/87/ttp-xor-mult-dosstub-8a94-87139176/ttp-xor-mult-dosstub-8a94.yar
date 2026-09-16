rule TTP_XOR_MULT_DOSStub_8a94 {
  strings:
    $key_8a94 = { de fc [2] aa e4 [2] ed e6 [2] aa f7 [2] e4 fb [2] e8 f1 [2] ff fa [2] e4 b4 [2] d9 }

  condition:
    any of them
}