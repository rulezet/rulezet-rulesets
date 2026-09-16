rule TTP_XOR_MULT_DOSStub_c714 {
  strings:
    $key_c714 = { 93 7c [2] e7 64 [2] a0 66 [2] e7 77 [2] a9 7b [2] a5 71 [2] b2 7a [2] a9 34 [2] 94 }

  condition:
    any of them
}