rule TTP_XOR_MULT_DOSStub_5a92 {
  strings:
    $key_5a92 = { 0e fa [2] 7a e2 [2] 3d e0 [2] 7a f1 [2] 34 fd [2] 38 f7 [2] 2f fc [2] 34 b2 [2] 09 }

  condition:
    any of them
}