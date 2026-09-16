rule TTP_XOR_MULT_DOSStub_4b95 {
  strings:
    $key_4b95 = { 1f fd [2] 6b e5 [2] 2c e7 [2] 6b f6 [2] 25 fa [2] 29 f0 [2] 3e fb [2] 25 b5 [2] 18 }

  condition:
    any of them
}