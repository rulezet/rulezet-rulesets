rule TTP_XOR_MULT_DOSStub_c0f7 {
  strings:
    $key_c0f7 = { 94 9f [2] e0 87 [2] a7 85 [2] e0 94 [2] ae 98 [2] a2 92 [2] b5 99 [2] ae d7 [2] 93 }

  condition:
    any of them
}