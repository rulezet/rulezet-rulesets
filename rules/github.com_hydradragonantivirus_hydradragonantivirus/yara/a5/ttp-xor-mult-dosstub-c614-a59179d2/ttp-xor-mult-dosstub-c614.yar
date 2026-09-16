rule TTP_XOR_MULT_DOSStub_c614 {
  strings:
    $key_c614 = { 92 7c [2] e6 64 [2] a1 66 [2] e6 77 [2] a8 7b [2] a4 71 [2] b3 7a [2] a8 34 [2] 95 }

  condition:
    any of them
}