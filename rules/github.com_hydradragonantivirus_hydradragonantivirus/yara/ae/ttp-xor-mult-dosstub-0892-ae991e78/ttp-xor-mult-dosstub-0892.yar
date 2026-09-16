rule TTP_XOR_MULT_DOSStub_0892 {
  strings:
    $key_0892 = { 5c fa [2] 28 e2 [2] 6f e0 [2] 28 f1 [2] 66 fd [2] 6a f7 [2] 7d fc [2] 66 b2 [2] 5b }

  condition:
    any of them
}