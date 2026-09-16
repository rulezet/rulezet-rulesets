rule TTP_XOR_MULT_DOSStub_2a99 {
  strings:
    $key_2a99 = { 7e f1 [2] 0a e9 [2] 4d eb [2] 0a fa [2] 44 f6 [2] 48 fc [2] 5f f7 [2] 44 b9 [2] 79 }

  condition:
    any of them
}