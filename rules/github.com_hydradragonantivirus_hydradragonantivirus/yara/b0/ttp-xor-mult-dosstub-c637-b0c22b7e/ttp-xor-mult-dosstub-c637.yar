rule TTP_XOR_MULT_DOSStub_c637 {
  strings:
    $key_c637 = { 92 5f [2] e6 47 [2] a1 45 [2] e6 54 [2] a8 58 [2] a4 52 [2] b3 59 [2] a8 17 [2] 95 }

  condition:
    any of them
}