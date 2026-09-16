rule TTP_XOR_MULT_DOSStub_7699 {
  strings:
    $key_7699 = { 22 f1 [2] 56 e9 [2] 11 eb [2] 56 fa [2] 18 f6 [2] 14 fc [2] 03 f7 [2] 18 b9 [2] 25 }

  condition:
    any of them
}