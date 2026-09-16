rule TTP_XOR_MULT_DOSStub_d692 {
  strings:
    $key_d692 = { 82 fa [2] f6 e2 [2] b1 e0 [2] f6 f1 [2] b8 fd [2] b4 f7 [2] a3 fc [2] b8 b2 [2] 85 }

  condition:
    any of them
}