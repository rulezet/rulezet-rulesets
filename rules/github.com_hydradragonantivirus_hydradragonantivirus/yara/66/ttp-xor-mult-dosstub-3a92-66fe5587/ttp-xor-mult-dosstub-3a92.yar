rule TTP_XOR_MULT_DOSStub_3a92 {
  strings:
    $key_3a92 = { 6e fa [2] 1a e2 [2] 5d e0 [2] 1a f1 [2] 54 fd [2] 58 f7 [2] 4f fc [2] 54 b2 [2] 69 }

  condition:
    any of them
}