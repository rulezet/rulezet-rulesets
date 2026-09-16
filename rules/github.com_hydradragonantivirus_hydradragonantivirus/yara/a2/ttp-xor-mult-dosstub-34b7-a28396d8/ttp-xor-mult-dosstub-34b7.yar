rule TTP_XOR_MULT_DOSStub_34b7 {
  strings:
    $key_34b7 = { 60 df [2] 14 c7 [2] 53 c5 [2] 14 d4 [2] 5a d8 [2] 56 d2 [2] 41 d9 [2] 5a 97 [2] 67 }

  condition:
    any of them
}