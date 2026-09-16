rule TTP_XOR_MULT_DOSStub_4a95 {
  strings:
    $key_4a95 = { 1e fd [2] 6a e5 [2] 2d e7 [2] 6a f6 [2] 24 fa [2] 28 f0 [2] 3f fb [2] 24 b5 [2] 19 }

  condition:
    any of them
}