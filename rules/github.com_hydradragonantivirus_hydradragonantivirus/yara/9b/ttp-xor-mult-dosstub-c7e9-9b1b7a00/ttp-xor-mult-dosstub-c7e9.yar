rule TTP_XOR_MULT_DOSStub_c7e9 {
  strings:
    $key_c7e9 = { 93 81 [2] e7 99 [2] a0 9b [2] e7 8a [2] a9 86 [2] a5 8c [2] b2 87 [2] a9 c9 [2] 94 }

  condition:
    any of them
}