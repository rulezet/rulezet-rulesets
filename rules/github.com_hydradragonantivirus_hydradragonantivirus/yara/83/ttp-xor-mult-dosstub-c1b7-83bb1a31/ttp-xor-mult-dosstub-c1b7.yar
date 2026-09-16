rule TTP_XOR_MULT_DOSStub_c1b7 {
  strings:
    $key_c1b7 = { 95 df [2] e1 c7 [2] a6 c5 [2] e1 d4 [2] af d8 [2] a3 d2 [2] b4 d9 [2] af 97 [2] 92 }

  condition:
    any of them
}