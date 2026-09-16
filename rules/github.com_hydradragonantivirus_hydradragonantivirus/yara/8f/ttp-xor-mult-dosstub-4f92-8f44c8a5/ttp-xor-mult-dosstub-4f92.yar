rule TTP_XOR_MULT_DOSStub_4f92 {
  strings:
    $key_4f92 = { 1b fa [2] 6f e2 [2] 28 e0 [2] 6f f1 [2] 21 fd [2] 2d f7 [2] 3a fc [2] 21 b2 [2] 1c }

  condition:
    any of them
}