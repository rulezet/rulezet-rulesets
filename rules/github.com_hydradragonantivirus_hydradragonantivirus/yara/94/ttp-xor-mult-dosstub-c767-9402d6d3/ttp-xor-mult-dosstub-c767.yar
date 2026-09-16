rule TTP_XOR_MULT_DOSStub_c767 {
  strings:
    $key_c767 = { 93 0f [2] e7 17 [2] a0 15 [2] e7 04 [2] a9 08 [2] a5 02 [2] b2 09 [2] a9 47 [2] 94 }

  condition:
    any of them
}