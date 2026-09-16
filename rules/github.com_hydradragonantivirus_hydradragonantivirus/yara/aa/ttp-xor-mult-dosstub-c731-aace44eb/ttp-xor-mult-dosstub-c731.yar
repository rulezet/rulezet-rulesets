rule TTP_XOR_MULT_DOSStub_c731 {
  strings:
    $key_c731 = { 93 59 [2] e7 41 [2] a0 43 [2] e7 52 [2] a9 5e [2] a5 54 [2] b2 5f [2] a9 11 [2] 94 }

  condition:
    any of them
}