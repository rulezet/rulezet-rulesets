rule TTP_XOR_MULT_DOSStub_d194 {
  strings:
    $key_d194 = { 85 fc [2] f1 e4 [2] b6 e6 [2] f1 f7 [2] bf fb [2] b3 f1 [2] a4 fa [2] bf b4 [2] 82 }

  condition:
    any of them
}