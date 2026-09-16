rule TTP_XOR_MULT_DOSStub_4b99 {
  strings:
    $key_4b99 = { 1f f1 [2] 6b e9 [2] 2c eb [2] 6b fa [2] 25 f6 [2] 29 fc [2] 3e f7 [2] 25 b9 [2] 18 }

  condition:
    any of them
}