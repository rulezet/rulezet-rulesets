rule TTP_XOR_MULT_DOSStub_2b99 {
  strings:
    $key_2b99 = { 7f f1 [2] 0b e9 [2] 4c eb [2] 0b fa [2] 45 f6 [2] 49 fc [2] 5e f7 [2] 45 b9 [2] 78 }

  condition:
    any of them
}