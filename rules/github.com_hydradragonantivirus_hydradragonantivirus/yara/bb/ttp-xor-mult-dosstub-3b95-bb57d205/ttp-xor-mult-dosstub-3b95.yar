rule TTP_XOR_MULT_DOSStub_3b95 {
  strings:
    $key_3b95 = { 6f fd [2] 1b e5 [2] 5c e7 [2] 1b f6 [2] 55 fa [2] 59 f0 [2] 4e fb [2] 55 b5 [2] 68 }

  condition:
    any of them
}