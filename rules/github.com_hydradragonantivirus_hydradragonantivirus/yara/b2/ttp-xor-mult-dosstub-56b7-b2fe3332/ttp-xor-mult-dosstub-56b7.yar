rule TTP_XOR_MULT_DOSStub_56b7 {
  strings:
    $key_56b7 = { 02 df [2] 76 c7 [2] 31 c5 [2] 76 d4 [2] 38 d8 [2] 34 d2 [2] 23 d9 [2] 38 97 [2] 05 }

  condition:
    any of them
}