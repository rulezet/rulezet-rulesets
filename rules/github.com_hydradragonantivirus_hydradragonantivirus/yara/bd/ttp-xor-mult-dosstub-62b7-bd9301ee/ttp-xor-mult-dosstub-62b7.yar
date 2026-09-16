rule TTP_XOR_MULT_DOSStub_62b7 {
  strings:
    $key_62b7 = { 36 df [2] 42 c7 [2] 05 c5 [2] 42 d4 [2] 0c d8 [2] 00 d2 [2] 17 d9 [2] 0c 97 [2] 31 }

  condition:
    any of them
}