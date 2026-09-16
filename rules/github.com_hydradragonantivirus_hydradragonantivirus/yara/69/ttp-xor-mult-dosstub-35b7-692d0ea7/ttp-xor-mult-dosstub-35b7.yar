rule TTP_XOR_MULT_DOSStub_35b7 {
  strings:
    $key_35b7 = { 61 df [2] 15 c7 [2] 52 c5 [2] 15 d4 [2] 5b d8 [2] 57 d2 [2] 40 d9 [2] 5b 97 [2] 66 }

  condition:
    any of them
}