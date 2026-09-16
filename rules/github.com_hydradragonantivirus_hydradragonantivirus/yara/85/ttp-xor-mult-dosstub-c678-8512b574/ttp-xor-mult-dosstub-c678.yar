rule TTP_XOR_MULT_DOSStub_c678 {
  strings:
    $key_c678 = { 92 10 [2] e6 08 [2] a1 0a [2] e6 1b [2] a8 17 [2] a4 1d [2] b3 16 [2] a8 58 [2] 95 }

  condition:
    any of them
}