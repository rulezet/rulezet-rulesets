rule TTP_XOR_MULT_DOSStub_4046 {
  strings:
    $key_4046 = { 14 2e [2] 60 36 [2] 27 34 [2] 60 25 [2] 2e 29 [2] 22 23 [2] 35 28 [2] 2e 66 [2] 13 }

  condition:
    any of them
}