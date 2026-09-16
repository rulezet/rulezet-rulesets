rule TTP_XOR_MULT_DOSStub_c7f7 {
  strings:
    $key_c7f7 = { 93 9f [2] e7 87 [2] a0 85 [2] e7 94 [2] a9 98 [2] a5 92 [2] b2 99 [2] a9 d7 [2] 94 }

  condition:
    any of them
}