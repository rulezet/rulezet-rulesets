rule TTP_XOR_MULT_DOSStub_29b7 {
  strings:
    $key_29b7 = { 7d df [2] 09 c7 [2] 4e c5 [2] 09 d4 [2] 47 d8 [2] 4b d2 [2] 5c d9 [2] 47 97 [2] 7a }

  condition:
    any of them
}