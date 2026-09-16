rule TTP_XOR_MULT_DOSStub_44b7 {
  strings:
    $key_44b7 = { 10 df [2] 64 c7 [2] 23 c5 [2] 64 d4 [2] 2a d8 [2] 26 d2 [2] 31 d9 [2] 2a 97 [2] 17 }

  condition:
    any of them
}