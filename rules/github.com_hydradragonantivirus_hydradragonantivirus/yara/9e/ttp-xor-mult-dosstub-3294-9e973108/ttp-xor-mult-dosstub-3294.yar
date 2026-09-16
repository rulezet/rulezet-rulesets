rule TTP_XOR_MULT_DOSStub_3294 {
  strings:
    $key_3294 = { 66 fc [2] 12 e4 [2] 55 e6 [2] 12 f7 [2] 5c fb [2] 50 f1 [2] 47 fa [2] 5c b4 [2] 61 }

  condition:
    any of them
}