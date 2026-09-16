rule TTP_XOR_MULT_DOSStub_25b7 {
  strings:
    $key_25b7 = { 71 df [2] 05 c7 [2] 42 c5 [2] 05 d4 [2] 4b d8 [2] 47 d2 [2] 50 d9 [2] 4b 97 [2] 76 }

  condition:
    any of them
}