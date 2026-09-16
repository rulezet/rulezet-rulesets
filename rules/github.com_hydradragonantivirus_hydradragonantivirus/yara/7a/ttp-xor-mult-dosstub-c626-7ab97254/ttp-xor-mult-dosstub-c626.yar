rule TTP_XOR_MULT_DOSStub_c626 {
  strings:
    $key_c626 = { 92 4e [2] e6 56 [2] a1 54 [2] e6 45 [2] a8 49 [2] a4 43 [2] b3 48 [2] a8 06 [2] 95 }

  condition:
    any of them
}