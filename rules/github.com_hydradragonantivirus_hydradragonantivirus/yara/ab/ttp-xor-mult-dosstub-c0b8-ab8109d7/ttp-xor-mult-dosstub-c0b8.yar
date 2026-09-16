rule TTP_XOR_MULT_DOSStub_c0b8 {
  strings:
    $key_c0b8 = { 94 d0 [2] e0 c8 [2] a7 ca [2] e0 db [2] ae d7 [2] a2 dd [2] b5 d6 [2] ae 98 [2] 93 }

  condition:
    any of them
}