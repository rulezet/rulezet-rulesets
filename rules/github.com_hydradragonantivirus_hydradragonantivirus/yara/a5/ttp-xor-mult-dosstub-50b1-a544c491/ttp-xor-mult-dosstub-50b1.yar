rule TTP_XOR_MULT_DOSStub_50b1 {
  strings:
    $key_50b1 = { 04 d9 [2] 70 c1 [2] 37 c3 [2] 70 d2 [2] 3e de [2] 32 d4 [2] 25 df [2] 3e 91 [2] 03 }

  condition:
    any of them
}