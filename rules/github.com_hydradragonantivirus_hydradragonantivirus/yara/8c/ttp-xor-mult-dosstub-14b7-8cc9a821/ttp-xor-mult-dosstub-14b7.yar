rule TTP_XOR_MULT_DOSStub_14b7 {
  strings:
    $key_14b7 = { 40 df [2] 34 c7 [2] 73 c5 [2] 34 d4 [2] 7a d8 [2] 76 d2 [2] 61 d9 [2] 7a 97 [2] 47 }

  condition:
    any of them
}