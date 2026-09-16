rule TTP_XOR_MULT_DOSStub_c774 {
  strings:
    $key_c774 = { 93 1c [2] e7 04 [2] a0 06 [2] e7 17 [2] a9 1b [2] a5 11 [2] b2 1a [2] a9 54 [2] 94 }

  condition:
    any of them
}