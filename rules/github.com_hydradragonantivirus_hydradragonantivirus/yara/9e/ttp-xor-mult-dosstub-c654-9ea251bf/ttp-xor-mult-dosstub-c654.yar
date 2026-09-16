rule TTP_XOR_MULT_DOSStub_c654 {
  strings:
    $key_c654 = { 92 3c [2] e6 24 [2] a1 26 [2] e6 37 [2] a8 3b [2] a4 31 [2] b3 3a [2] a8 74 [2] 95 }

  condition:
    any of them
}