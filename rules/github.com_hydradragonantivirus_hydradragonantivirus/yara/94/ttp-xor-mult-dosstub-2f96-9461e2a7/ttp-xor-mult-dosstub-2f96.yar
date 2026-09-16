rule TTP_XOR_MULT_DOSStub_2f96 {
  strings:
    $key_2f96 = { 7b fe [2] 0f e6 [2] 48 e4 [2] 0f f5 [2] 41 f9 [2] 4d f3 [2] 5a f8 [2] 41 b6 [2] 7c }

  condition:
    any of them
}