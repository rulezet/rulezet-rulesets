rule TTP_XOR_MULT_DOSStub_1b99 {
  strings:
    $key_1b99 = { 4f f1 [2] 3b e9 [2] 7c eb [2] 3b fa [2] 75 f6 [2] 79 fc [2] 6e f7 [2] 75 b9 [2] 48 }

  condition:
    any of them
}