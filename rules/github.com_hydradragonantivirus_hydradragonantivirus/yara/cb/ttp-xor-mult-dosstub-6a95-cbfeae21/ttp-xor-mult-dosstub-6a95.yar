rule TTP_XOR_MULT_DOSStub_6a95 {
  strings:
    $key_6a95 = { 3e fd [2] 4a e5 [2] 0d e7 [2] 4a f6 [2] 04 fa [2] 08 f0 [2] 1f fb [2] 04 b5 [2] 39 }

  condition:
    any of them
}