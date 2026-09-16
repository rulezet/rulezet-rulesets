rule TTP_XOR_MULT_DOSStub_c675 {
  strings:
    $key_c675 = { 92 1d [2] e6 05 [2] a1 07 [2] e6 16 [2] a8 1a [2] a4 10 [2] b3 1b [2] a8 55 [2] 95 }

  condition:
    any of them
}