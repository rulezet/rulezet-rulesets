rule TTP_XOR_MULT_DOSStub_7299 {
  strings:
    $key_7299 = { 26 f1 [2] 52 e9 [2] 15 eb [2] 52 fa [2] 1c f6 [2] 10 fc [2] 07 f7 [2] 1c b9 [2] 21 }

  condition:
    any of them
}