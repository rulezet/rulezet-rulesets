rule TTP_XOR_MULT_DOSStub_e294 {
  strings:
    $key_e294 = { b6 fc [2] c2 e4 [2] 85 e6 [2] c2 f7 [2] 8c fb [2] 80 f1 [2] 97 fa [2] 8c b4 [2] b1 }

  condition:
    any of them
}