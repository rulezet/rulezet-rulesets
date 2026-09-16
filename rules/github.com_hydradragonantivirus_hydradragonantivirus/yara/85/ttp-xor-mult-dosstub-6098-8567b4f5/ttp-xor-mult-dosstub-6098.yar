rule TTP_XOR_MULT_DOSStub_6098 {
  strings:
    $key_6098 = { 34 f0 [2] 40 e8 [2] 07 ea [2] 40 fb [2] 0e f7 [2] 02 fd [2] 15 f6 [2] 0e b8 [2] 33 }

  condition:
    any of them
}