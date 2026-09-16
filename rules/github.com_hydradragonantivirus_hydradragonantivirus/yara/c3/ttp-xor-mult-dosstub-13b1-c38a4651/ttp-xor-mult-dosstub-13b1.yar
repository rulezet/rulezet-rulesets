rule TTP_XOR_MULT_DOSStub_13b1 {
  strings:
    $key_13b1 = { 47 d9 [2] 33 c1 [2] 74 c3 [2] 33 d2 [2] 7d de [2] 71 d4 [2] 66 df [2] 7d 91 [2] 40 }

  condition:
    any of them
}