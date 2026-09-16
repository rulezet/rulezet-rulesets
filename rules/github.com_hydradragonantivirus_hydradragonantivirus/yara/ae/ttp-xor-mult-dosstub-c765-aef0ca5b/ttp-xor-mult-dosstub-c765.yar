rule TTP_XOR_MULT_DOSStub_c765 {
  strings:
    $key_c765 = { 93 0d [2] e7 15 [2] a0 17 [2] e7 06 [2] a9 0a [2] a5 00 [2] b2 0b [2] a9 45 [2] 94 }

  condition:
    any of them
}