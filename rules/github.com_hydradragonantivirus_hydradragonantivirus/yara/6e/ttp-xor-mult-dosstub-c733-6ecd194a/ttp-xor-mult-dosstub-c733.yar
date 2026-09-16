rule TTP_XOR_MULT_DOSStub_c733 {
  strings:
    $key_c733 = { 93 5b [2] e7 43 [2] a0 41 [2] e7 50 [2] a9 5c [2] a5 56 [2] b2 5d [2] a9 13 [2] 94 }

  condition:
    any of them
}