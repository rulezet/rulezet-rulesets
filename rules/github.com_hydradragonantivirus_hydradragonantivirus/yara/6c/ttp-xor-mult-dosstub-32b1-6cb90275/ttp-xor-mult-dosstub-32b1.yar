rule TTP_XOR_MULT_DOSStub_32b1 {
  strings:
    $key_32b1 = { 66 d9 [2] 12 c1 [2] 55 c3 [2] 12 d2 [2] 5c de [2] 50 d4 [2] 47 df [2] 5c 91 [2] 61 }

  condition:
    any of them
}