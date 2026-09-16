rule TTP_XOR_MULT_DOSStub_6e95 {
  strings:
    $key_6e95 = { 3a fd [2] 4e e5 [2] 09 e7 [2] 4e f6 [2] 00 fa [2] 0c f0 [2] 1b fb [2] 00 b5 [2] 3d }

  condition:
    any of them
}