rule TTP_XOR_MULT_DOSStub_5792 {
  strings:
    $key_5792 = { 03 fa [2] 77 e2 [2] 30 e0 [2] 77 f1 [2] 39 fd [2] 35 f7 [2] 22 fc [2] 39 b2 [2] 04 }

  condition:
    any of them
}