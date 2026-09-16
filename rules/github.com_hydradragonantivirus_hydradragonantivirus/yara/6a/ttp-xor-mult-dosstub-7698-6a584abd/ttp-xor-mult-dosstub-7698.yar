rule TTP_XOR_MULT_DOSStub_7698 {
  strings:
    $key_7698 = { 22 f0 [2] 56 e8 [2] 11 ea [2] 56 fb [2] 18 f7 [2] 14 fd [2] 03 f6 [2] 18 b8 [2] 25 }

  condition:
    any of them
}