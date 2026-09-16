rule TTP_XOR_MULT_DOSStub_c0a6 {
  strings:
    $key_c0a6 = { 94 ce [2] e0 d6 [2] a7 d4 [2] e0 c5 [2] ae c9 [2] a2 c3 [2] b5 c8 [2] ae 86 [2] 93 }

  condition:
    any of them
}