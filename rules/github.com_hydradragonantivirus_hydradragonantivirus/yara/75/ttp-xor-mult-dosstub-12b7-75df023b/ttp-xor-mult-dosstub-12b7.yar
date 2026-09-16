rule TTP_XOR_MULT_DOSStub_12b7 {
  strings:
    $key_12b7 = { 46 df [2] 32 c7 [2] 75 c5 [2] 32 d4 [2] 7c d8 [2] 70 d2 [2] 67 d9 [2] 7c 97 [2] 41 }

  condition:
    any of them
}