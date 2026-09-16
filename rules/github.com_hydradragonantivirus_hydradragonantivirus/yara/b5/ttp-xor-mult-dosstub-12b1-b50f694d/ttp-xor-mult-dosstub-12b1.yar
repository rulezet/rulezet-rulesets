rule TTP_XOR_MULT_DOSStub_12b1 {
  strings:
    $key_12b1 = { 46 d9 [2] 32 c1 [2] 75 c3 [2] 32 d2 [2] 7c de [2] 70 d4 [2] 67 df [2] 7c 91 [2] 41 }

  condition:
    any of them
}