rule TTP_XOR_MULT_DOSStub_2b95 {
  strings:
    $key_2b95 = { 7f fd [2] 0b e5 [2] 4c e7 [2] 0b f6 [2] 45 fa [2] 49 f0 [2] 5e fb [2] 45 b5 [2] 78 }

  condition:
    any of them
}