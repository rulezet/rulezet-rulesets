rule TTP_XOR_MULT_DOSStub_1695 {
  strings:
    $key_1695 = { 42 fd [2] 36 e5 [2] 71 e7 [2] 36 f6 [2] 78 fa [2] 74 f0 [2] 63 fb [2] 78 b5 [2] 45 }

  condition:
    any of them
}