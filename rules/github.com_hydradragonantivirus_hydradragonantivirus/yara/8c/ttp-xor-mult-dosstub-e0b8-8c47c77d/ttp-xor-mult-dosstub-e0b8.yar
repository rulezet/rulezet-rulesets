rule TTP_XOR_MULT_DOSStub_e0b8 {
  strings:
    $key_e0b8 = { b4 d0 [2] c0 c8 [2] 87 ca [2] c0 db [2] 8e d7 [2] 82 dd [2] 95 d6 [2] 8e 98 [2] b3 }

  condition:
    any of them
}