rule TTP_XOR_MULT_DOSStub_c643 {
  strings:
    $key_c643 = { 92 2b [2] e6 33 [2] a1 31 [2] e6 20 [2] a8 2c [2] a4 26 [2] b3 2d [2] a8 63 [2] 95 }

  condition:
    any of them
}