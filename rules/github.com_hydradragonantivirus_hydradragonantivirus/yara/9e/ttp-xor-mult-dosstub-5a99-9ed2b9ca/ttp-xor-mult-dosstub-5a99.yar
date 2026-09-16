rule TTP_XOR_MULT_DOSStub_5a99 {
  strings:
    $key_5a99 = { 0e f1 [2] 7a e9 [2] 3d eb [2] 7a fa [2] 34 f6 [2] 38 fc [2] 2f f7 [2] 34 b9 [2] 09 }

  condition:
    any of them
}