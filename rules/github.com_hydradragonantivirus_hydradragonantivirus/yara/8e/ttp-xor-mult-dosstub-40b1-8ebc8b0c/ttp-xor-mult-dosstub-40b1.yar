rule TTP_XOR_MULT_DOSStub_40b1 {
  strings:
    $key_40b1 = { 14 d9 [2] 60 c1 [2] 27 c3 [2] 60 d2 [2] 2e de [2] 22 d4 [2] 35 df [2] 2e 91 [2] 13 }

  condition:
    any of them
}