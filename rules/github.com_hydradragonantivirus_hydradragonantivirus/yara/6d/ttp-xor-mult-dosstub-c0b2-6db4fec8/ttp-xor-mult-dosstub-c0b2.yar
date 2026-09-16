rule TTP_XOR_MULT_DOSStub_c0b2 {
  strings:
    $key_c0b2 = { 94 da [2] e0 c2 [2] a7 c0 [2] e0 d1 [2] ae dd [2] a2 d7 [2] b5 dc [2] ae 92 [2] 93 }

  condition:
    any of them
}