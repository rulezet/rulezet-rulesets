rule TTP_XOR_MULT_DOSStub_c644 {
  strings:
    $key_c644 = { 92 2c [2] e6 34 [2] a1 36 [2] e6 27 [2] a8 2b [2] a4 21 [2] b3 2a [2] a8 64 [2] 95 }

  condition:
    any of them
}