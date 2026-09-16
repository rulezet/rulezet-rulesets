rule TTP_XOR_MULT_DOSStub_3392 {
  strings:
    $key_3392 = { 67 fa [2] 13 e2 [2] 54 e0 [2] 13 f1 [2] 5d fd [2] 51 f7 [2] 46 fc [2] 5d b2 [2] 60 }

  condition:
    any of them
}