rule TTP_XOR_MULT_DOSStub_0f92 {
  strings:
    $key_0f92 = { 5b fa [2] 2f e2 [2] 68 e0 [2] 2f f1 [2] 61 fd [2] 6d f7 [2] 7a fc [2] 61 b2 [2] 5c }

  condition:
    any of them
}