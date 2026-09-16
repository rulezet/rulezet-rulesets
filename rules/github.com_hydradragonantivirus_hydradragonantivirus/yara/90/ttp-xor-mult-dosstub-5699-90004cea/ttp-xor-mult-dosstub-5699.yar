rule TTP_XOR_MULT_DOSStub_5699 {
  strings:
    $key_5699 = { 02 f1 [2] 76 e9 [2] 31 eb [2] 76 fa [2] 38 f6 [2] 34 fc [2] 23 f7 [2] 38 b9 [2] 05 }

  condition:
    any of them
}