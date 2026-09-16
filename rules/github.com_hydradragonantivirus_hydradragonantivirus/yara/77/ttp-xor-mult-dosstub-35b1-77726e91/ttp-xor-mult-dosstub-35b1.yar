rule TTP_XOR_MULT_DOSStub_35b1 {
  strings:
    $key_35b1 = { 61 d9 [2] 15 c1 [2] 52 c3 [2] 15 d2 [2] 5b de [2] 57 d4 [2] 40 df [2] 5b 91 [2] 66 }

  condition:
    any of them
}