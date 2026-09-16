rule TTP_XOR_MULT_DOSStub_8887 {
  strings:
    $key_8887 = { dc ef [2] a8 f7 [2] ef f5 [2] a8 e4 [2] e6 e8 [2] ea e2 [2] fd e9 [2] e6 a7 [2] db }

  condition:
    any of them
}