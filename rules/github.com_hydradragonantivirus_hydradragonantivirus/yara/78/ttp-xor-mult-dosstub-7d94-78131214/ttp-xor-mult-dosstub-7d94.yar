rule TTP_XOR_MULT_DOSStub_7d94 {
  strings:
    $key_7d94 = { 29 fc [2] 5d e4 [2] 1a e6 [2] 5d f7 [2] 13 fb [2] 1f f1 [2] 08 fa [2] 13 b4 [2] 2e }

  condition:
    any of them
}