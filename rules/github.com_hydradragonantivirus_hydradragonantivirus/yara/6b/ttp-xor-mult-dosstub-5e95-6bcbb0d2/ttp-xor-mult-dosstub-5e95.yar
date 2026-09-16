rule TTP_XOR_MULT_DOSStub_5e95 {
  strings:
    $key_5e95 = { 0a fd [2] 7e e5 [2] 39 e7 [2] 7e f6 [2] 30 fa [2] 3c f0 [2] 2b fb [2] 30 b5 [2] 0d }

  condition:
    any of them
}