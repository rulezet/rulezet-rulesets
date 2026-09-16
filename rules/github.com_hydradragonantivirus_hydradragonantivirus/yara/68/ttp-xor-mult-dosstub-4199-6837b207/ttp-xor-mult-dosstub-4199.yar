rule TTP_XOR_MULT_DOSStub_4199 {
  strings:
    $key_4199 = { 15 f1 [2] 61 e9 [2] 26 eb [2] 61 fa [2] 2f f6 [2] 23 fc [2] 34 f7 [2] 2f b9 [2] 12 }

  condition:
    any of them
}