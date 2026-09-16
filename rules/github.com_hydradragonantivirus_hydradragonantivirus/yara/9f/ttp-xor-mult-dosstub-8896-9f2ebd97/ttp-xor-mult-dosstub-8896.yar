rule TTP_XOR_MULT_DOSStub_8896 {
  strings:
    $key_8896 = { dc fe [2] a8 e6 [2] ef e4 [2] a8 f5 [2] e6 f9 [2] ea f3 [2] fd f8 [2] e6 b6 [2] db }

  condition:
    any of them
}