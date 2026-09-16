rule TTP_XOR_MULT_DOSStub_c657 {
  strings:
    $key_c657 = { 92 3f [2] e6 27 [2] a1 25 [2] e6 34 [2] a8 38 [2] a4 32 [2] b3 39 [2] a8 77 [2] 95 }

  condition:
    any of them
}