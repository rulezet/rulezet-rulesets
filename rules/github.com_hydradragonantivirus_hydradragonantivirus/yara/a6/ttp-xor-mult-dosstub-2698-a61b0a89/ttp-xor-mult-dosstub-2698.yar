rule TTP_XOR_MULT_DOSStub_2698 {
  strings:
    $key_2698 = { 72 f0 [2] 06 e8 [2] 41 ea [2] 06 fb [2] 48 f7 [2] 44 fd [2] 53 f6 [2] 48 b8 [2] 75 }

  condition:
    any of them
}