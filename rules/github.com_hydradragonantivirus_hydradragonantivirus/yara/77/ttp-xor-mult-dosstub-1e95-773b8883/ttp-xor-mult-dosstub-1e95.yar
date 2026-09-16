rule TTP_XOR_MULT_DOSStub_1e95 {
  strings:
    $key_1e95 = { 4a fd [2] 3e e5 [2] 79 e7 [2] 3e f6 [2] 70 fa [2] 7c f0 [2] 6b fb [2] 70 b5 [2] 4d }

  condition:
    any of them
}