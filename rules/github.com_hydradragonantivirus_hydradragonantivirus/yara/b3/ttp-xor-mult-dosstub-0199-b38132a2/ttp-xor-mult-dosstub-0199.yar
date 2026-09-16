rule TTP_XOR_MULT_DOSStub_0199 {
  strings:
    $key_0199 = { 55 f1 [2] 21 e9 [2] 66 eb [2] 21 fa [2] 6f f6 [2] 63 fc [2] 74 f7 [2] 6f b9 [2] 52 }

  condition:
    any of them
}