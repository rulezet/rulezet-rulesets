rule TTP_XOR_MULT_DOSStub_c645 {
  strings:
    $key_c645 = { 92 2d [2] e6 35 [2] a1 37 [2] e6 26 [2] a8 2a [2] a4 20 [2] b3 2b [2] a8 65 [2] 95 }

  condition:
    any of them
}