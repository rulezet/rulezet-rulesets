rule TTP_XOR_MULT_DOSStub_d892 {
  strings:
    $key_d892 = { 8c fa [2] f8 e2 [2] bf e0 [2] f8 f1 [2] b6 fd [2] ba f7 [2] ad fc [2] b6 b2 [2] 8b }

  condition:
    any of them
}