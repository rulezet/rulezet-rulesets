rule TTP_XOR_MULT_DOSStub_5399 {
  strings:
    $key_5399 = { 07 f1 [2] 73 e9 [2] 34 eb [2] 73 fa [2] 3d f6 [2] 31 fc [2] 26 f7 [2] 3d b9 [2] 00 }

  condition:
    any of them
}