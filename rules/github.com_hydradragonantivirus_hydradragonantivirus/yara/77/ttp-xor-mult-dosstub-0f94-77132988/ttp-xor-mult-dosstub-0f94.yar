rule TTP_XOR_MULT_DOSStub_0f94 {
  strings:
    $key_0f94 = { 5b fc [2] 2f e4 [2] 68 e6 [2] 2f f7 [2] 61 fb [2] 6d f1 [2] 7a fa [2] 61 b4 [2] 5c }

  condition:
    any of them
}