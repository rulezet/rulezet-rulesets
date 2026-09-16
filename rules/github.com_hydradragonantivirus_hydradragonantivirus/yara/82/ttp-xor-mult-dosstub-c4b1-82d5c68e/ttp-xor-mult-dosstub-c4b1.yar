rule TTP_XOR_MULT_DOSStub_c4b1 {
  strings:
    $key_c4b1 = { 90 d9 [2] e4 c1 [2] a3 c3 [2] e4 d2 [2] aa de [2] a6 d4 [2] b1 df [2] aa 91 [2] 97 }

  condition:
    any of them
}