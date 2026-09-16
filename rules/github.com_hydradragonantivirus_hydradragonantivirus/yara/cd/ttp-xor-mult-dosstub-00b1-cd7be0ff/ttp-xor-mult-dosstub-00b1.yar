rule TTP_XOR_MULT_DOSStub_00b1 {
  strings:
    $key_00b1 = { 54 d9 [2] 20 c1 [2] 67 c3 [2] 20 d2 [2] 6e de [2] 62 d4 [2] 75 df [2] 6e 91 [2] 53 }

  condition:
    any of them
}