rule TTP_XOR_MULT_DOSStub_1294 {
  strings:
    $key_1294 = { 46 fc [2] 32 e4 [2] 75 e6 [2] 32 f7 [2] 7c fb [2] 70 f1 [2] 67 fa [2] 7c b4 [2] 41 }

  condition:
    any of them
}