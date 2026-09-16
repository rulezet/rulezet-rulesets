rule TTP_XOR_MULT_DOSStub_c477 {
  strings:
    $key_c477 = { 90 1f [2] e4 07 [2] a3 05 [2] e4 14 [2] aa 18 [2] a6 12 [2] b1 19 [2] aa 57 [2] 97 }

  condition:
    any of them
}