rule TTP_XOR_MULT_DOSStub_1d94 {
  strings:
    $key_1d94 = { 49 fc [2] 3d e4 [2] 7a e6 [2] 3d f7 [2] 73 fb [2] 7f f1 [2] 68 fa [2] 73 b4 [2] 4e }

  condition:
    any of them
}