rule TTP_XOR_MULT_DOSStub_c050 {
  strings:
    $key_c050 = { 94 38 [2] e0 20 [2] a7 22 [2] e0 33 [2] ae 3f [2] a2 35 [2] b5 3e [2] ae 70 [2] 93 }

  condition:
    any of them
}