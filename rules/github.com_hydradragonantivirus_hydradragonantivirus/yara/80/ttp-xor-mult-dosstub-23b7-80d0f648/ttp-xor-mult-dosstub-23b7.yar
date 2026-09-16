rule TTP_XOR_MULT_DOSStub_23b7 {
  strings:
    $key_23b7 = { 77 df [2] 03 c7 [2] 44 c5 [2] 03 d4 [2] 4d d8 [2] 41 d2 [2] 56 d9 [2] 4d 97 [2] 70 }

  condition:
    any of them
}