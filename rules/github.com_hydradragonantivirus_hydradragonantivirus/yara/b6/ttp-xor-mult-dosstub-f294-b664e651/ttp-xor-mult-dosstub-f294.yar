rule TTP_XOR_MULT_DOSStub_f294 {
  strings:
    $key_f294 = { a6 fc [2] d2 e4 [2] 95 e6 [2] d2 f7 [2] 9c fb [2] 90 f1 [2] 87 fa [2] 9c b4 [2] a1 }

  condition:
    any of them
}