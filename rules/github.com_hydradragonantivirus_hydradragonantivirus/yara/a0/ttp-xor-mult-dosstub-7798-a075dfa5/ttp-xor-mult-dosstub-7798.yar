rule TTP_XOR_MULT_DOSStub_7798 {
  strings:
    $key_7798 = { 23 f0 [2] 57 e8 [2] 10 ea [2] 57 fb [2] 19 f7 [2] 15 fd [2] 02 f6 [2] 19 b8 [2] 24 }

  condition:
    any of them
}