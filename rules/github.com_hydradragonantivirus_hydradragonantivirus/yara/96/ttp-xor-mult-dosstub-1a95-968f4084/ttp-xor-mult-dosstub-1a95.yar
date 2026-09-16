rule TTP_XOR_MULT_DOSStub_1a95 {
  strings:
    $key_1a95 = { 4e fd [2] 3a e5 [2] 7d e7 [2] 3a f6 [2] 74 fa [2] 78 f0 [2] 6f fb [2] 74 b5 [2] 49 }

  condition:
    any of them
}