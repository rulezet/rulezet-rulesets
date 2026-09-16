rule TTP_XOR_MULT_DOSStub_2290 {
  strings:
    $key_2290 = { 76 f8 [2] 02 e0 [2] 45 e2 [2] 02 f3 [2] 4c ff [2] 40 f5 [2] 57 fe [2] 4c b0 [2] 71 }

  condition:
    any of them
}