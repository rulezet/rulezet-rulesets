rule TTP_XOR_MULT_DOSStub_1892 {
  strings:
    $key_1892 = { 4c fa [2] 38 e2 [2] 7f e0 [2] 38 f1 [2] 76 fd [2] 7a f7 [2] 6d fc [2] 76 b2 [2] 4b }

  condition:
    any of them
}