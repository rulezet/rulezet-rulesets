rule TTP_XOR_MULT_DOSStub_7d95 {
  strings:
    $key_7d95 = { 29 fd [2] 5d e5 [2] 1a e7 [2] 5d f6 [2] 13 fa [2] 1f f0 [2] 08 fb [2] 13 b5 [2] 2e }

  condition:
    any of them
}