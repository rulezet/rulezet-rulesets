rule TTP_XOR_MULT_DOSStub_c747 {
  strings:
    $key_c747 = { 93 2f [2] e7 37 [2] a0 35 [2] e7 24 [2] a9 28 [2] a5 22 [2] b2 29 [2] a9 67 [2] 94 }

  condition:
    any of them
}