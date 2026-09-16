rule TTP_XOR_MULT_DOSStub_c749 {
  strings:
    $key_c749 = { 93 21 [2] e7 39 [2] a0 3b [2] e7 2a [2] a9 26 [2] a5 2c [2] b2 27 [2] a9 69 [2] 94 }

  condition:
    any of them
}