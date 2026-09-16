rule TTP_XOR_MULT_DOSStub_c761 {
  strings:
    $key_c761 = { 93 09 [2] e7 11 [2] a0 13 [2] e7 02 [2] a9 0e [2] a5 04 [2] b2 0f [2] a9 41 [2] 94 }

  condition:
    any of them
}