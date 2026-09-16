rule TTP_XOR_MULT_DOSStub_c600 {
  strings:
    $key_c600 = { 92 68 [2] e6 70 [2] a1 72 [2] e6 63 [2] a8 6f [2] a4 65 [2] b3 6e [2] a8 20 [2] 95 }

  condition:
    any of them
}