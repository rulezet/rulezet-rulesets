rule TTP_XOR_MULT_DOSStub_c0b5 {
  strings:
    $key_c0b5 = { 94 dd [2] e0 c5 [2] a7 c7 [2] e0 d6 [2] ae da [2] a2 d0 [2] b5 db [2] ae 95 [2] 93 }

  condition:
    any of them
}