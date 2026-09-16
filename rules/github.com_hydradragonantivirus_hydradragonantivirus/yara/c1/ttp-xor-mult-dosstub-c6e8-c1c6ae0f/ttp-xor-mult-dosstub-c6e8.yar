rule TTP_XOR_MULT_DOSStub_c6e8 {
  strings:
    $key_c6e8 = { 92 80 [2] e6 98 [2] a1 9a [2] e6 8b [2] a8 87 [2] a4 8d [2] b3 86 [2] a8 c8 [2] 95 }

  condition:
    any of them
}