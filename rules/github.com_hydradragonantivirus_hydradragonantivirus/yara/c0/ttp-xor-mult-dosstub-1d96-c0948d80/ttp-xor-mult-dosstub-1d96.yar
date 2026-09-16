rule TTP_XOR_MULT_DOSStub_1d96 {
  strings:
    $key_1d96 = { 49 fe [2] 3d e6 [2] 7a e4 [2] 3d f5 [2] 73 f9 [2] 7f f3 [2] 68 f8 [2] 73 b6 [2] 4e }

  condition:
    any of them
}