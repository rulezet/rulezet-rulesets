rule TTP_XOR_MULT_DOSStub_d392 {
  strings:
    $key_d392 = { 87 fa [2] f3 e2 [2] b4 e0 [2] f3 f1 [2] bd fd [2] b1 f7 [2] a6 fc [2] bd b2 [2] 80 }

  condition:
    any of them
}