rule TTP_XOR_MULT_DOSStub_c7a8 {
  strings:
    $key_c7a8 = { 93 c0 [2] e7 d8 [2] a0 da [2] e7 cb [2] a9 c7 [2] a5 cd [2] b2 c6 [2] a9 88 [2] 94 }

  condition:
    any of them
}