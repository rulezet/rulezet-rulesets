rule TTP_XOR_MULT_DOSStub_1499 {
  strings:
    $key_1499 = { 40 f1 [2] 34 e9 [2] 73 eb [2] 34 fa [2] 7a f6 [2] 76 fc [2] 61 f7 [2] 7a b9 [2] 47 }

  condition:
    any of them
}