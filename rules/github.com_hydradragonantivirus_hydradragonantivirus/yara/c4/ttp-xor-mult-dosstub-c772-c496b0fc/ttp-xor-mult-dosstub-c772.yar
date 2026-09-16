rule TTP_XOR_MULT_DOSStub_c772 {
  strings:
    $key_c772 = { 93 1a [2] e7 02 [2] a0 00 [2] e7 11 [2] a9 1d [2] a5 17 [2] b2 1c [2] a9 52 [2] 94 }

  condition:
    any of them
}