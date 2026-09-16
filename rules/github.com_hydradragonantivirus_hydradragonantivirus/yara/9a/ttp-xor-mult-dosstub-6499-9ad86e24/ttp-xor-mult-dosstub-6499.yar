rule TTP_XOR_MULT_DOSStub_6499 {
  strings:
    $key_6499 = { 30 f1 [2] 44 e9 [2] 03 eb [2] 44 fa [2] 0a f6 [2] 06 fc [2] 11 f7 [2] 0a b9 [2] 37 }

  condition:
    any of them
}