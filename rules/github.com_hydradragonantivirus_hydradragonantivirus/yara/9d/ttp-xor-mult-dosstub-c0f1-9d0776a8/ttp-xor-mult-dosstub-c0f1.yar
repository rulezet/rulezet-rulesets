rule TTP_XOR_MULT_DOSStub_c0f1 {
  strings:
    $key_c0f1 = { 94 99 [2] e0 81 [2] a7 83 [2] e0 92 [2] ae 9e [2] a2 94 [2] b5 9f [2] ae d1 [2] 93 }

  condition:
    any of them
}