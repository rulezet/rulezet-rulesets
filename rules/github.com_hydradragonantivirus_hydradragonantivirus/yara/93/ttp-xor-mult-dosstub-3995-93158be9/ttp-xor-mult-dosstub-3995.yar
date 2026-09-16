rule TTP_XOR_MULT_DOSStub_3995 {
  strings:
    $key_3995 = { 6d fd [2] 19 e5 [2] 5e e7 [2] 19 f6 [2] 57 fa [2] 5b f0 [2] 4c fb [2] 57 b5 [2] 6a }

  condition:
    any of them
}