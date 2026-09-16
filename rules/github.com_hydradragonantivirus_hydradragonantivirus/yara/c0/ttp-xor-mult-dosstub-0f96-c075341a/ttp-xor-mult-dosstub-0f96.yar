rule TTP_XOR_MULT_DOSStub_0f96 {
  strings:
    $key_0f96 = { 5b fe [2] 2f e6 [2] 68 e4 [2] 2f f5 [2] 61 f9 [2] 6d f3 [2] 7a f8 [2] 61 b6 [2] 5c }

  condition:
    any of them
}