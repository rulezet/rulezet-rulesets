rule TTP_XOR_MULT_DOSStub_5199 {
  strings:
    $key_5199 = { 05 f1 [2] 71 e9 [2] 36 eb [2] 71 fa [2] 3f f6 [2] 33 fc [2] 24 f7 [2] 3f b9 [2] 02 }

  condition:
    any of them
}