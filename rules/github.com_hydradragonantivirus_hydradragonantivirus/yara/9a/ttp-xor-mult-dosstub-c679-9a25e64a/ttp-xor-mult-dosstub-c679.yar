rule TTP_XOR_MULT_DOSStub_c679 {
  strings:
    $key_c679 = { 92 11 [2] e6 09 [2] a1 0b [2] e6 1a [2] a8 16 [2] a4 1c [2] b3 17 [2] a8 59 [2] 95 }

  condition:
    any of them
}