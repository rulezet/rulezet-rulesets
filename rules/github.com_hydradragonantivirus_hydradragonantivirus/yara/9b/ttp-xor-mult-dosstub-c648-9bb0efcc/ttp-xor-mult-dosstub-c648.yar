rule TTP_XOR_MULT_DOSStub_c648 {
  strings:
    $key_c648 = { 92 20 [2] e6 38 [2] a1 3a [2] e6 2b [2] a8 27 [2] a4 2d [2] b3 26 [2] a8 68 [2] 95 }

  condition:
    any of them
}