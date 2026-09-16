rule TTP_XOR_MULT_DOSStub_5995 {
  strings:
    $key_5995 = { 0d fd [2] 79 e5 [2] 3e e7 [2] 79 f6 [2] 37 fa [2] 3b f0 [2] 2c fb [2] 37 b5 [2] 0a }

  condition:
    any of them
}