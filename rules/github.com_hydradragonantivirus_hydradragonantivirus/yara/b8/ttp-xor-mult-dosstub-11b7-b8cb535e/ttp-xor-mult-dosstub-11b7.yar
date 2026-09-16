rule TTP_XOR_MULT_DOSStub_11b7 {
  strings:
    $key_11b7 = { 45 df [2] 31 c7 [2] 76 c5 [2] 31 d4 [2] 7f d8 [2] 73 d2 [2] 64 d9 [2] 7f 97 [2] 42 }

  condition:
    any of them
}