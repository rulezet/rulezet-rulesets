rule TTP_XOR_MULT_DOSStub_4892 {
  strings:
    $key_4892 = { 1c fa [2] 68 e2 [2] 2f e0 [2] 68 f1 [2] 26 fd [2] 2a f7 [2] 3d fc [2] 26 b2 [2] 1b }

  condition:
    any of them
}