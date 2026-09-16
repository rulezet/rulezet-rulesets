rule TTP_XOR_MULT_DOSStub_1699 {
  strings:
    $key_1699 = { 42 f1 [2] 36 e9 [2] 71 eb [2] 36 fa [2] 78 f6 [2] 74 fc [2] 63 f7 [2] 78 b9 [2] 45 }

  condition:
    any of them
}