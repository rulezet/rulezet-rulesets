rule TTP_XOR_MULT_DOSStub_6595 {
  strings:
    $key_6595 = { 31 fd [2] 45 e5 [2] 02 e7 [2] 45 f6 [2] 0b fa [2] 07 f0 [2] 10 fb [2] 0b b5 [2] 36 }

  condition:
    any of them
}