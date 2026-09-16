rule TTP_XOR_MULT_DOSStub_0d94 {
  strings:
    $key_0d94 = { 59 fc [2] 2d e4 [2] 6a e6 [2] 2d f7 [2] 63 fb [2] 6f f1 [2] 78 fa [2] 63 b4 [2] 5e }

  condition:
    any of them
}