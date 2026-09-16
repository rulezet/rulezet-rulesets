rule TTP_XOR_MULT_DOSStub_3599 {
  strings:
    $key_3599 = { 61 f1 [2] 15 e9 [2] 52 eb [2] 15 fa [2] 5b f6 [2] 57 fc [2] 40 f7 [2] 5b b9 [2] 66 }

  condition:
    any of them
}