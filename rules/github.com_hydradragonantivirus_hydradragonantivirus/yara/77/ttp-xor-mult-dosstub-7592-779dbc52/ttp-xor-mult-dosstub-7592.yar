rule TTP_XOR_MULT_DOSStub_7592 {
  strings:
    $key_7592 = { 21 fa [2] 55 e2 [2] 12 e0 [2] 55 f1 [2] 1b fd [2] 17 f7 [2] 00 fc [2] 1b b2 [2] 26 }

  condition:
    any of them
}