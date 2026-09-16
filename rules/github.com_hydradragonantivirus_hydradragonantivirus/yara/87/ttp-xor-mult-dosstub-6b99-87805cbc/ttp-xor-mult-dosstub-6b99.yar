rule TTP_XOR_MULT_DOSStub_6b99 {
  strings:
    $key_6b99 = { 3f f1 [2] 4b e9 [2] 0c eb [2] 4b fa [2] 05 f6 [2] 09 fc [2] 1e f7 [2] 05 b9 [2] 38 }

  condition:
    any of them
}