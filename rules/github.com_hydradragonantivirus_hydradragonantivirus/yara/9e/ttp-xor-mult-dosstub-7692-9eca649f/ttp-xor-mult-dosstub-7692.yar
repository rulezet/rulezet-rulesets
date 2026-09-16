rule TTP_XOR_MULT_DOSStub_7692 {
  strings:
    $key_7692 = { 22 fa [2] 56 e2 [2] 11 e0 [2] 56 f1 [2] 18 fd [2] 14 f7 [2] 03 fc [2] 18 b2 [2] 25 }

  condition:
    any of them
}