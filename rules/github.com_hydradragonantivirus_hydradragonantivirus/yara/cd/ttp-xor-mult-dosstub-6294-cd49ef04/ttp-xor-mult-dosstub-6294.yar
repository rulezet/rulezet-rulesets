rule TTP_XOR_MULT_DOSStub_6294 {
  strings:
    $key_6294 = { 36 fc [2] 42 e4 [2] 05 e6 [2] 42 f7 [2] 0c fb [2] 00 f1 [2] 17 fa [2] 0c b4 [2] 31 }

  condition:
    any of them
}