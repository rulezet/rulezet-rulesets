rule TTP_XOR_MULT_DOSStub_5392 {
  strings:
    $key_5392 = { 07 fa [2] 73 e2 [2] 34 e0 [2] 73 f1 [2] 3d fd [2] 31 f7 [2] 26 fc [2] 3d b2 [2] 00 }

  condition:
    any of them
}