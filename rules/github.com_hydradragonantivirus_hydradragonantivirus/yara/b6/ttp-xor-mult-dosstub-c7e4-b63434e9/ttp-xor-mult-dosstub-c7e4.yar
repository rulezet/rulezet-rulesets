rule TTP_XOR_MULT_DOSStub_c7e4 {
  strings:
    $key_c7e4 = { 93 8c [2] e7 94 [2] a0 96 [2] e7 87 [2] a9 8b [2] a5 81 [2] b2 8a [2] a9 c4 [2] 94 }

  condition:
    any of them
}