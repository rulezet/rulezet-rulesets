rule TTP_XOR_MULT_DOSStub_0499 {
  strings:
    $key_0499 = { 50 f1 [2] 24 e9 [2] 63 eb [2] 24 fa [2] 6a f6 [2] 66 fc [2] 71 f7 [2] 6a b9 [2] 57 }

  condition:
    any of them
}