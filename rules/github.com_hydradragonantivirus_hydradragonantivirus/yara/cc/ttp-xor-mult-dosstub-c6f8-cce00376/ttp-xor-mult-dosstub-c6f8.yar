rule TTP_XOR_MULT_DOSStub_c6f8 {
  strings:
    $key_c6f8 = { 92 90 [2] e6 88 [2] a1 8a [2] e6 9b [2] a8 97 [2] a4 9d [2] b3 96 [2] a8 d8 [2] 95 }

  condition:
    any of them
}