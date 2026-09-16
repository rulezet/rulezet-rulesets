rule TTP_XOR_MULT_DOSStub_1299 {
  strings:
    $key_1299 = { 46 f1 [2] 32 e9 [2] 75 eb [2] 32 fa [2] 7c f6 [2] 70 fc [2] 67 f7 [2] 7c b9 [2] 41 }

  condition:
    any of them
}