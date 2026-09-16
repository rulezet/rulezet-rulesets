rule TTP_XOR_MULT_DOSStub_c718 {
  strings:
    $key_c718 = { 93 70 [2] e7 68 [2] a0 6a [2] e7 7b [2] a9 77 [2] a5 7d [2] b2 76 [2] a9 38 [2] 94 }

  condition:
    any of them
}