rule TTP_XOR_MULT_DOSStub_c615 {
  strings:
    $key_c615 = { 92 7d [2] e6 65 [2] a1 67 [2] e6 76 [2] a8 7a [2] a4 70 [2] b3 7b [2] a8 35 [2] 95 }

  condition:
    any of them
}