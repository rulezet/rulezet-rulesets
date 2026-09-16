rule TTP_XOR_MULT_DOSStub_c647 {
  strings:
    $key_c647 = { 92 2f [2] e6 37 [2] a1 35 [2] e6 24 [2] a8 28 [2] a4 22 [2] b3 29 [2] a8 67 [2] 95 }

  condition:
    any of them
}