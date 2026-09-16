rule TTP_XOR_MULT_DOSStub_d192 {
  strings:
    $key_d192 = { 85 fa [2] f1 e2 [2] b6 e0 [2] f1 f1 [2] bf fd [2] b3 f7 [2] a4 fc [2] bf b2 [2] 82 }

  condition:
    any of them
}