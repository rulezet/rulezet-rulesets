rule TTP_XOR_MULT_DOSStub_5892 {
  strings:
    $key_5892 = { 0c fa [2] 78 e2 [2] 3f e0 [2] 78 f1 [2] 36 fd [2] 3a f7 [2] 2d fc [2] 36 b2 [2] 0b }

  condition:
    any of them
}