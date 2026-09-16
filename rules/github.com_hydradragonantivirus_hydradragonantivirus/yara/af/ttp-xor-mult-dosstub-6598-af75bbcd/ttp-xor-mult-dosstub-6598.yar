rule TTP_XOR_MULT_DOSStub_6598 {
  strings:
    $key_6598 = { 31 f0 [2] 45 e8 [2] 02 ea [2] 45 fb [2] 0b f7 [2] 07 fd [2] 10 f6 [2] 0b b8 [2] 36 }

  condition:
    any of them
}