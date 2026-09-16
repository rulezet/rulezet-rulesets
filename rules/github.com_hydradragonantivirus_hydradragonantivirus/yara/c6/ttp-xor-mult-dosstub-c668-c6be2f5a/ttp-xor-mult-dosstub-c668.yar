rule TTP_XOR_MULT_DOSStub_c668 {
  strings:
    $key_c668 = { 92 00 [2] e6 18 [2] a1 1a [2] e6 0b [2] a8 07 [2] a4 0d [2] b3 06 [2] a8 48 [2] 95 }

  condition:
    any of them
}