rule TTP_XOR_MULT_DOSStub_e592 {
  strings:
    $key_e592 = { b1 fa [2] c5 e2 [2] 82 e0 [2] c5 f1 [2] 8b fd [2] 87 f7 [2] 90 fc [2] 8b b2 [2] b6 }

  condition:
    any of them
}