rule TTP_XOR_MULT_DOSStub_6d94 {
  strings:
    $key_6d94 = { 39 fc [2] 4d e4 [2] 0a e6 [2] 4d f7 [2] 03 fb [2] 0f f1 [2] 18 fa [2] 03 b4 [2] 3e }

  condition:
    any of them
}