rule TTP_XOR_MULT_DOSStub_c727 {
  strings:
    $key_c727 = { 93 4f [2] e7 57 [2] a0 55 [2] e7 44 [2] a9 48 [2] a5 42 [2] b2 49 [2] a9 07 [2] 94 }

  condition:
    any of them
}