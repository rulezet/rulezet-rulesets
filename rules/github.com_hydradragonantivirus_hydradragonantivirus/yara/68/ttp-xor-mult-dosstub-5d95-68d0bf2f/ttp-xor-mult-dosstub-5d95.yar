rule TTP_XOR_MULT_DOSStub_5d95 {
  strings:
    $key_5d95 = { 09 fd [2] 7d e5 [2] 3a e7 [2] 7d f6 [2] 33 fa [2] 3f f0 [2] 28 fb [2] 33 b5 [2] 0e }

  condition:
    any of them
}