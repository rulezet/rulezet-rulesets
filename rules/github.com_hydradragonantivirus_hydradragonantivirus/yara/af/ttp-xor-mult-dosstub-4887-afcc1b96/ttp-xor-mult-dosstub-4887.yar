rule TTP_XOR_MULT_DOSStub_4887 {
  strings:
    $key_4887 = { 1c ef [2] 68 f7 [2] 2f f5 [2] 68 e4 [2] 26 e8 [2] 2a e2 [2] 3d e9 [2] 26 a7 [2] 1b }

  condition:
    any of them
}