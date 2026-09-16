rule TTP_XOR_MULT_DOSStub_c712 {
  strings:
    $key_c712 = { 93 7a [2] e7 62 [2] a0 60 [2] e7 71 [2] a9 7d [2] a5 77 [2] b2 7c [2] a9 32 [2] 94 }

  condition:
    any of them
}