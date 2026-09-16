rule TTP_XOR_MULT_DOSStub_5f96 {
  strings:
    $key_5f96 = { 0b fe [2] 7f e6 [2] 38 e4 [2] 7f f5 [2] 31 f9 [2] 3d f3 [2] 2a f8 [2] 31 b6 [2] 0c }

  condition:
    any of them
}