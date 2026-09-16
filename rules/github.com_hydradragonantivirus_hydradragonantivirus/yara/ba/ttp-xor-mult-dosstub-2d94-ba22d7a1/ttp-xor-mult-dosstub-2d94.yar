rule TTP_XOR_MULT_DOSStub_2d94 {
  strings:
    $key_2d94 = { 79 fc [2] 0d e4 [2] 4a e6 [2] 0d f7 [2] 43 fb [2] 4f f1 [2] 58 fa [2] 43 b4 [2] 7e }

  condition:
    any of them
}