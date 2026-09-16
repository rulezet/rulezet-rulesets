rule TTP_XOR_MULT_DOSStub_75b1 {
  strings:
    $key_75b1 = { 21 d9 [2] 55 c1 [2] 12 c3 [2] 55 d2 [2] 1b de [2] 17 d4 [2] 00 df [2] 1b 91 [2] 26 }

  condition:
    any of them
}