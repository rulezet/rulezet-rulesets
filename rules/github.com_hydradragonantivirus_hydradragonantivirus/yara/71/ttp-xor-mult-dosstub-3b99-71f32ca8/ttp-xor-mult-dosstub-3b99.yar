rule TTP_XOR_MULT_DOSStub_3b99 {
  strings:
    $key_3b99 = { 6f f1 [2] 1b e9 [2] 5c eb [2] 1b fa [2] 55 f6 [2] 59 fc [2] 4e f7 [2] 55 b9 [2] 68 }

  condition:
    any of them
}