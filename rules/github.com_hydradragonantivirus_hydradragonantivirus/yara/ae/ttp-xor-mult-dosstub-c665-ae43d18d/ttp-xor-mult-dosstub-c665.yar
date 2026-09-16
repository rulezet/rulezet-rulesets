rule TTP_XOR_MULT_DOSStub_c665 {
  strings:
    $key_c665 = { 92 0d [2] e6 15 [2] a1 17 [2] e6 06 [2] a8 0a [2] a4 00 [2] b3 0b [2] a8 45 [2] 95 }

  condition:
    any of them
}