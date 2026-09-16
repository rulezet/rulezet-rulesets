rule TTP_XOR_MULT_DOSStub_7799 {
  strings:
    $key_7799 = { 23 f1 [2] 57 e9 [2] 10 eb [2] 57 fa [2] 19 f6 [2] 15 fc [2] 02 f7 [2] 19 b9 [2] 24 }

  condition:
    any of them
}