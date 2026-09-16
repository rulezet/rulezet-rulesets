rule TTP_XOR_MULT_DOSStub_5290 {
  strings:
    $key_5290 = { 06 f8 [2] 72 e0 [2] 35 e2 [2] 72 f3 [2] 3c ff [2] 30 f5 [2] 27 fe [2] 3c b0 [2] 01 }

  condition:
    any of them
}