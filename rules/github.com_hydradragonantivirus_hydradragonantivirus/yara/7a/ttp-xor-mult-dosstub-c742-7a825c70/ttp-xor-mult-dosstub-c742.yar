rule TTP_XOR_MULT_DOSStub_c742 {
  strings:
    $key_c742 = { 93 2a [2] e7 32 [2] a0 30 [2] e7 21 [2] a9 2d [2] a5 27 [2] b2 2c [2] a9 62 [2] 94 }

  condition:
    any of them
}