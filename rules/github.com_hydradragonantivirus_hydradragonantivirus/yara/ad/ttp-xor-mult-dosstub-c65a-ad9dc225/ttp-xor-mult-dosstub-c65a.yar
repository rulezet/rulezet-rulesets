rule TTP_XOR_MULT_DOSStub_c65a {
  strings:
    $key_c65a = { 92 32 [2] e6 2a [2] a1 28 [2] e6 39 [2] a8 35 [2] a4 3f [2] b3 34 [2] a8 7a [2] 95 }

  condition:
    any of them
}