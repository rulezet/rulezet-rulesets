rule TTP_XOR_MULT_DOSStub_21b7 {
  strings:
    $key_21b7 = { 75 df [2] 01 c7 [2] 46 c5 [2] 01 d4 [2] 4f d8 [2] 43 d2 [2] 54 d9 [2] 4f 97 [2] 72 }

  condition:
    any of them
}