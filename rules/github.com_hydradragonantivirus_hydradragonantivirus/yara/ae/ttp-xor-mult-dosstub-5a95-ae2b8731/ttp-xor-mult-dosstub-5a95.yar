rule TTP_XOR_MULT_DOSStub_5a95 {
  strings:
    $key_5a95 = { 0e fd [2] 7a e5 [2] 3d e7 [2] 7a f6 [2] 34 fa [2] 38 f0 [2] 2f fb [2] 34 b5 [2] 09 }

  condition:
    any of them
}