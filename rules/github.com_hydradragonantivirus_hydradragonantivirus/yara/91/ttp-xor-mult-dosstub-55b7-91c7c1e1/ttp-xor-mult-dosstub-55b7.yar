rule TTP_XOR_MULT_DOSStub_55b7 {
  strings:
    $key_55b7 = { 01 df [2] 75 c7 [2] 32 c5 [2] 75 d4 [2] 3b d8 [2] 37 d2 [2] 20 d9 [2] 3b 97 [2] 06 }

  condition:
    any of them
}