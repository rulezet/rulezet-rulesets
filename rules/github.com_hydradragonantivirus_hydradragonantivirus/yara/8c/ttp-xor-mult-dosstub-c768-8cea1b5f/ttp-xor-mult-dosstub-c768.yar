rule TTP_XOR_MULT_DOSStub_c768 {
  strings:
    $key_c768 = { 93 00 [2] e7 18 [2] a0 1a [2] e7 0b [2] a9 07 [2] a5 0d [2] b2 06 [2] a9 48 [2] 94 }

  condition:
    any of them
}