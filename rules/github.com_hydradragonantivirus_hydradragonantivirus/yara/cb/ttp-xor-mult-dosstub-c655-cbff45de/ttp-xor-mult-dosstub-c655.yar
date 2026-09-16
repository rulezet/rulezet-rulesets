rule TTP_XOR_MULT_DOSStub_c655 {
  strings:
    $key_c655 = { 92 3d [2] e6 25 [2] a1 27 [2] e6 36 [2] a8 3a [2] a4 30 [2] b3 3b [2] a8 75 [2] 95 }

  condition:
    any of them
}