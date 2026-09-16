rule TTP_XOR_MULT_DOSStub_32b7 {
  strings:
    $key_32b7 = { 66 df [2] 12 c7 [2] 55 c5 [2] 12 d4 [2] 5c d8 [2] 50 d2 [2] 47 d9 [2] 5c 97 [2] 61 }

  condition:
    any of them
}