rule TTP_XOR_MULT_DOSStub_c64a {
  strings:
    $key_c64a = { 92 22 [2] e6 3a [2] a1 38 [2] e6 29 [2] a8 25 [2] a4 2f [2] b3 24 [2] a8 6a [2] 95 }

  condition:
    any of them
}