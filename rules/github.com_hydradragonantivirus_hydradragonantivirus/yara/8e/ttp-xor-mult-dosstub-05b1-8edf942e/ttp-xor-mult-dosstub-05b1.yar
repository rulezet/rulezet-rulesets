rule TTP_XOR_MULT_DOSStub_05b1 {
  strings:
    $key_05b1 = { 51 d9 [2] 25 c1 [2] 62 c3 [2] 25 d2 [2] 6b de [2] 67 d4 [2] 70 df [2] 6b 91 [2] 56 }

  condition:
    any of them
}