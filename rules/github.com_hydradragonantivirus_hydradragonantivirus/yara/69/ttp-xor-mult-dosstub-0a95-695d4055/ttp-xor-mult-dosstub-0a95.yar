rule TTP_XOR_MULT_DOSStub_0a95 {
  strings:
    $key_0a95 = { 5e fd [2] 2a e5 [2] 6d e7 [2] 2a f6 [2] 64 fa [2] 68 f0 [2] 7f fb [2] 64 b5 [2] 59 }

  condition:
    any of them
}