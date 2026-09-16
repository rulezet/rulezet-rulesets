rule TTP_XOR_MULT_DOSStub_3896 {
  strings:
    $key_3896 = { 6c fe [2] 18 e6 [2] 5f e4 [2] 18 f5 [2] 56 f9 [2] 5a f3 [2] 4d f8 [2] 56 b6 [2] 6b }

  condition:
    any of them
}