rule TTP_XOR_MULT_DOSStub_2098 {
  strings:
    $key_2098 = { 74 f0 [2] 00 e8 [2] 47 ea [2] 00 fb [2] 4e f7 [2] 42 fd [2] 55 f6 [2] 4e b8 [2] 73 }

  condition:
    any of them
}