rule TTP_XOR_MULT_DOSStub_c672 {
  strings:
    $key_c672 = { 92 1a [2] e6 02 [2] a1 00 [2] e6 11 [2] a8 1d [2] a4 17 [2] b3 1c [2] a8 52 [2] 95 }

  condition:
    any of them
}