rule TTP_XOR_MULT_DOSStub_30b1 {
  strings:
    $key_30b1 = { 64 d9 [2] 10 c1 [2] 57 c3 [2] 10 d2 [2] 5e de [2] 52 d4 [2] 45 df [2] 5e 91 [2] 63 }

  condition:
    any of them
}