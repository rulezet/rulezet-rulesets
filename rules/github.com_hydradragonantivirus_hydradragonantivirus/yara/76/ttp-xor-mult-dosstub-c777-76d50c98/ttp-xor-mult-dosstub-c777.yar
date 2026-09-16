rule TTP_XOR_MULT_DOSStub_c777 {
  strings:
    $key_c777 = { 93 1f [2] e7 07 [2] a0 05 [2] e7 14 [2] a9 18 [2] a5 12 [2] b2 19 [2] a9 57 [2] 94 }

  condition:
    any of them
}