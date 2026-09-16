rule TTP_XOR_MULT_DOSStub_c7e2 {
  strings:
    $key_c7e2 = { 93 8a [2] e7 92 [2] a0 90 [2] e7 81 [2] a9 8d [2] a5 87 [2] b2 8c [2] a9 c2 [2] 94 }

  condition:
    any of them
}