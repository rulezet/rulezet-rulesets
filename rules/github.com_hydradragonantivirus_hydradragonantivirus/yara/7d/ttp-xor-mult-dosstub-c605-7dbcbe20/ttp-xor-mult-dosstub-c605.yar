rule TTP_XOR_MULT_DOSStub_c605 {
  strings:
    $key_c605 = { 92 6d [2] e6 75 [2] a1 77 [2] e6 66 [2] a8 6a [2] a4 60 [2] b3 6b [2] a8 25 [2] 95 }

  condition:
    any of them
}