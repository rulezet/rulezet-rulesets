rule TTP_XOR_MULT_DOSStub_c3d6 {
  strings:
    $key_c3d6 = { 97 be [2] e3 a6 [2] a4 a4 [2] e3 b5 [2] ad b9 [2] a1 b3 [2] b6 b8 [2] ad f6 [2] 90 }

  condition:
    any of them
}