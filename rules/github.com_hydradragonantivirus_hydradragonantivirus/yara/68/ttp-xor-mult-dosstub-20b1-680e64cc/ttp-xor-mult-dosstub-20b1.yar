rule TTP_XOR_MULT_DOSStub_20b1 {
  strings:
    $key_20b1 = { 74 d9 [2] 00 c1 [2] 47 c3 [2] 00 d2 [2] 4e de [2] 42 d4 [2] 55 df [2] 4e 91 [2] 73 }

  condition:
    any of them
}