rule TTP_XOR_MULT_DOSStub_c627 {
  strings:
    $key_c627 = { 92 4f [2] e6 57 [2] a1 55 [2] e6 44 [2] a8 48 [2] a4 42 [2] b3 49 [2] a8 07 [2] 95 }

  condition:
    any of them
}