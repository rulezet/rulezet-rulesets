rule TTP_XOR_MULT_DOSStub_c7f5 {
  strings:
    $key_c7f5 = { 93 9d [2] e7 85 [2] a0 87 [2] e7 96 [2] a9 9a [2] a5 90 [2] b2 9b [2] a9 d5 [2] 94 }

  condition:
    any of them
}