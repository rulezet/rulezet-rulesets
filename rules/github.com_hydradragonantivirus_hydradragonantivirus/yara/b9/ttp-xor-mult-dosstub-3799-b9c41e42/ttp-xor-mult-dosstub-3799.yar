rule TTP_XOR_MULT_DOSStub_3799 {
  strings:
    $key_3799 = { 63 f1 [2] 17 e9 [2] 50 eb [2] 17 fa [2] 59 f6 [2] 55 fc [2] 42 f7 [2] 59 b9 [2] 64 }

  condition:
    any of them
}