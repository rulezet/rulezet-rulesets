rule TTP_XOR_MULT_DOSStub_c6e7 {
  strings:
    $key_c6e7 = { 92 8f [2] e6 97 [2] a1 95 [2] e6 84 [2] a8 88 [2] a4 82 [2] b3 89 [2] a8 c7 [2] 95 }

  condition:
    any of them
}