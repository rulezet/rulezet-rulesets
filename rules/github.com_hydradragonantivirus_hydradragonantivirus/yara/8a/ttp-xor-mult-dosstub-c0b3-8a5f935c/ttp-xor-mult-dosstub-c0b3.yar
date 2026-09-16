rule TTP_XOR_MULT_DOSStub_c0b3 {
  strings:
    $key_c0b3 = { 94 db [2] e0 c3 [2] a7 c1 [2] e0 d0 [2] ae dc [2] a2 d6 [2] b5 dd [2] ae 93 [2] 93 }

  condition:
    any of them
}