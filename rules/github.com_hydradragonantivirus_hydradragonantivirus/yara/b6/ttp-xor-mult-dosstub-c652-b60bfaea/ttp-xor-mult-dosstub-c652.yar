rule TTP_XOR_MULT_DOSStub_c652 {
  strings:
    $key_c652 = { 92 3a [2] e6 22 [2] a1 20 [2] e6 31 [2] a8 3d [2] a4 37 [2] b3 3c [2] a8 72 [2] 95 }

  condition:
    any of them
}