rule TTP_XOR_MULT_DOSStub_7199 {
  strings:
    $key_7199 = { 25 f1 [2] 51 e9 [2] 16 eb [2] 51 fa [2] 1f f6 [2] 13 fc [2] 04 f7 [2] 1f b9 [2] 22 }

  condition:
    any of them
}