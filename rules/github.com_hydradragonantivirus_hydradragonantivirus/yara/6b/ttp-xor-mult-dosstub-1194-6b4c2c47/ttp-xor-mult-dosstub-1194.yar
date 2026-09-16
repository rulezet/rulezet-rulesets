rule TTP_XOR_MULT_DOSStub_1194 {
  strings:
    $key_1194 = { 45 fc [2] 31 e4 [2] 76 e6 [2] 31 f7 [2] 7f fb [2] 73 f1 [2] 64 fa [2] 7f b4 [2] 42 }

  condition:
    any of them
}