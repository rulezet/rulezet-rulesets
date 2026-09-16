rule TTP_XOR_MULT_DOSStub_0599 {
  strings:
    $key_0599 = { 51 f1 [2] 25 e9 [2] 62 eb [2] 25 fa [2] 6b f6 [2] 67 fc [2] 70 f7 [2] 6b b9 [2] 56 }

  condition:
    any of them
}