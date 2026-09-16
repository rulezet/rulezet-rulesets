rule TTP_XOR_MULT_DOSStub_33b1 {
  strings:
    $key_33b1 = { 67 d9 [2] 13 c1 [2] 54 c3 [2] 13 d2 [2] 5d de [2] 51 d4 [2] 46 df [2] 5d 91 [2] 60 }

  condition:
    any of them
}