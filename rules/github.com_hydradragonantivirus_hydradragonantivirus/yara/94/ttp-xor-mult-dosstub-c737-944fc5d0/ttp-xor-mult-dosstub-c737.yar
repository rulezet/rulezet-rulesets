rule TTP_XOR_MULT_DOSStub_c737 {
  strings:
    $key_c737 = { 93 5f [2] e7 47 [2] a0 45 [2] e7 54 [2] a9 58 [2] a5 52 [2] b2 59 [2] a9 17 [2] 94 }

  condition:
    any of them
}