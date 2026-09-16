rule TTP_XOR_MULT_DOSStub_43b1 {
  strings:
    $key_43b1 = { 17 d9 [2] 63 c1 [2] 24 c3 [2] 63 d2 [2] 2d de [2] 21 d4 [2] 36 df [2] 2d 91 [2] 10 }

  condition:
    any of them
}