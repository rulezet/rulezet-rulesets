rule TTP_XOR_MULT_DOSStub_c0d7 {
  strings:
    $key_c0d7 = { 94 bf [2] e0 a7 [2] a7 a5 [2] e0 b4 [2] ae b8 [2] a2 b2 [2] b5 b9 [2] ae f7 [2] 93 }

  condition:
    any of them
}