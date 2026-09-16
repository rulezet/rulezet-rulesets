rule TTP_XOR_MULT_DOSStub_66b7 {
  strings:
    $key_66b7 = { 32 df [2] 46 c7 [2] 01 c5 [2] 46 d4 [2] 08 d8 [2] 04 d2 [2] 13 d9 [2] 08 97 [2] 35 }

  condition:
    any of them
}