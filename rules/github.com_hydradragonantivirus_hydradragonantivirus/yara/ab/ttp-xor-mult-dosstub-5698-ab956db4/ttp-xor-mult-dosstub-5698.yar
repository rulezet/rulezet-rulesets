rule TTP_XOR_MULT_DOSStub_5698 {
  strings:
    $key_5698 = { 02 f0 [2] 76 e8 [2] 31 ea [2] 76 fb [2] 38 f7 [2] 34 fd [2] 23 f6 [2] 38 b8 [2] 05 }

  condition:
    any of them
}