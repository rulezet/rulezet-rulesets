rule TTP_XOR_MULT_DOSStub_0d96 {
  strings:
    $key_0d96 = { 59 fe [2] 2d e6 [2] 6a e4 [2] 2d f5 [2] 63 f9 [2] 6f f3 [2] 78 f8 [2] 63 b6 [2] 5e }

  condition:
    any of them
}