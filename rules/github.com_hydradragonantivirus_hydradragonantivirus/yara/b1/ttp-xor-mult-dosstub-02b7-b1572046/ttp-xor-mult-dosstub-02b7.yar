rule TTP_XOR_MULT_DOSStub_02b7 {
  strings:
    $key_02b7 = { 56 df [2] 22 c7 [2] 65 c5 [2] 22 d4 [2] 6c d8 [2] 60 d2 [2] 77 d9 [2] 6c 97 [2] 51 }

  condition:
    any of them
}