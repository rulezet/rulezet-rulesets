rule TTP_XOR_MULT_DOSStub_2699 {
  strings:
    $key_2699 = { 72 f1 [2] 06 e9 [2] 41 eb [2] 06 fa [2] 48 f6 [2] 44 fc [2] 53 f7 [2] 48 b9 [2] 75 }

  condition:
    any of them
}