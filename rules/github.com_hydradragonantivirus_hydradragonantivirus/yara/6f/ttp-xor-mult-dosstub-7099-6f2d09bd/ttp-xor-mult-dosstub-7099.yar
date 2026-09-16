rule TTP_XOR_MULT_DOSStub_7099 {
  strings:
    $key_7099 = { 24 f1 [2] 50 e9 [2] 17 eb [2] 50 fa [2] 1e f6 [2] 12 fc [2] 05 f7 [2] 1e b9 [2] 23 }

  condition:
    any of them
}