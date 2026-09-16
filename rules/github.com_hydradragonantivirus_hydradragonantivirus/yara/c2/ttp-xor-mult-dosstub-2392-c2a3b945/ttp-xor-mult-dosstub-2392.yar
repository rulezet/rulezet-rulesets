rule TTP_XOR_MULT_DOSStub_2392 {
  strings:
    $key_2392 = { 77 fa [2] 03 e2 [2] 44 e0 [2] 03 f1 [2] 4d fd [2] 41 f7 [2] 56 fc [2] 4d b2 [2] 70 }

  condition:
    any of them
}