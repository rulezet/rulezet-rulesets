rule TTP_XOR_MULT_DOSStub_71b7 {
  strings:
    $key_71b7 = { 25 df [2] 51 c7 [2] 16 c5 [2] 51 d4 [2] 1f d8 [2] 13 d2 [2] 04 d9 [2] 1f 97 [2] 22 }

  condition:
    any of them
}