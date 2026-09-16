rule TTP_XOR_MULT_DOSStub_2a95 {
  strings:
    $key_2a95 = { 7e fd [2] 0a e5 [2] 4d e7 [2] 0a f6 [2] 44 fa [2] 48 f0 [2] 5f fb [2] 44 b5 [2] 79 }

  condition:
    any of them
}