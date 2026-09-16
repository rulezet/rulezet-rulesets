rule TTP_XOR_MULT_DOSStub_7f94 {
  strings:
    $key_7f94 = { 2b fc [2] 5f e4 [2] 18 e6 [2] 5f f7 [2] 11 fb [2] 1d f1 [2] 0a fa [2] 11 b4 [2] 2c }

  condition:
    any of them
}