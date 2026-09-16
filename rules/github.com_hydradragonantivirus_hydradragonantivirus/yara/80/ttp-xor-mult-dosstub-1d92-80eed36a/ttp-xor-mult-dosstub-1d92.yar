rule TTP_XOR_MULT_DOSStub_1d92 {
  strings:
    $key_1d92 = { 49 fa [2] 3d e2 [2] 7a e0 [2] 3d f1 [2] 73 fd [2] 7f f7 [2] 68 fc [2] 73 b2 [2] 4e }

  condition:
    any of them
}