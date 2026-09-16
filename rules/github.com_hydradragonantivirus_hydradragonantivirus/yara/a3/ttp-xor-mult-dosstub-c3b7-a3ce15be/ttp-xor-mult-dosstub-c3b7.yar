rule TTP_XOR_MULT_DOSStub_c3b7 {
  strings:
    $key_c3b7 = { 97 df [2] e3 c7 [2] a4 c5 [2] e3 d4 [2] ad d8 [2] a1 d2 [2] b6 d9 [2] ad 97 [2] 90 }

  condition:
    any of them
}