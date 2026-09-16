rule TTP_XOR_MULT_DOSStub_fa94 {
  strings:
    $key_fa94 = { ae fc [2] da e4 [2] 9d e6 [2] da f7 [2] 94 fb [2] 98 f1 [2] 8f fa [2] 94 b4 [2] a9 }

  condition:
    any of them
}