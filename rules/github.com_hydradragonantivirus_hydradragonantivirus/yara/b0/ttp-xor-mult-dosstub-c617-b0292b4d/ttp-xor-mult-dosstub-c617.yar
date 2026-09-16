rule TTP_XOR_MULT_DOSStub_c617 {
  strings:
    $key_c617 = { 92 7f [2] e6 67 [2] a1 65 [2] e6 74 [2] a8 78 [2] a4 72 [2] b3 79 [2] a8 37 [2] 95 }

  condition:
    any of them
}