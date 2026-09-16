rule TTP_XOR_MULT_DOSStub_66b1 {
  strings:
    $key_66b1 = { 32 d9 [2] 46 c1 [2] 01 c3 [2] 46 d2 [2] 08 de [2] 04 d4 [2] 13 df [2] 08 91 [2] 35 }

  condition:
    any of them
}