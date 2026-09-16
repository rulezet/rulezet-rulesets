rule TTP_XOR_MULT_DOSStub_c0f6 {
  strings:
    $key_c0f6 = { 94 9e [2] e0 86 [2] a7 84 [2] e0 95 [2] ae 99 [2] a2 93 [2] b5 98 [2] ae d6 [2] 93 }

  condition:
    any of them
}