rule TTP_XOR_MULT_DOSStub_15b1 {
  strings:
    $key_15b1 = { 41 d9 [2] 35 c1 [2] 72 c3 [2] 35 d2 [2] 7b de [2] 77 d4 [2] 60 df [2] 7b 91 [2] 46 }

  condition:
    any of them
}