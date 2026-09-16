rule TTP_XOR_MULT_DOSStub_c6fa {
  strings:
    $key_c6fa = { 92 92 [2] e6 8a [2] a1 88 [2] e6 99 [2] a8 95 [2] a4 9f [2] b3 94 [2] a8 da [2] 95 }

  condition:
    any of them
}