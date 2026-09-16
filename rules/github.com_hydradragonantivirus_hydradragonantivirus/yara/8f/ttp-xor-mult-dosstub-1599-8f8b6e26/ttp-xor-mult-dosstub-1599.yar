rule TTP_XOR_MULT_DOSStub_1599 {
  strings:
    $key_1599 = { 41 f1 [2] 35 e9 [2] 72 eb [2] 35 fa [2] 7b f6 [2] 77 fc [2] 60 f7 [2] 7b b9 [2] 46 }

  condition:
    any of them
}