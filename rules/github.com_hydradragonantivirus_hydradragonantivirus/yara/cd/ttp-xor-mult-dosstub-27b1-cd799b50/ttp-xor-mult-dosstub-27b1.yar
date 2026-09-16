rule TTP_XOR_MULT_DOSStub_27b1 {
  strings:
    $key_27b1 = { 73 d9 [2] 07 c1 [2] 40 c3 [2] 07 d2 [2] 49 de [2] 45 d4 [2] 52 df [2] 49 91 [2] 74 }

  condition:
    any of them
}