rule TTP_XOR_MULT_DOSStub_60b1 {
  strings:
    $key_60b1 = { 34 d9 [2] 40 c1 [2] 07 c3 [2] 40 d2 [2] 0e de [2] 02 d4 [2] 15 df [2] 0e 91 [2] 33 }

  condition:
    any of them
}