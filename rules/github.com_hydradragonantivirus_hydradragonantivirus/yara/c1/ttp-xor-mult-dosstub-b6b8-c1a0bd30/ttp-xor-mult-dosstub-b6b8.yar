rule TTP_XOR_MULT_DOSStub_b6b8 {
  strings:
    $key_b6b8 = { e2 d0 [2] 96 c8 [2] d1 ca [2] 96 db [2] d8 d7 [2] d4 dd [2] c3 d6 [2] d8 98 [2] e5 }

  condition:
    any of them
}