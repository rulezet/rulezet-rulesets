rule TTP_XOR_MULT_DOSStub_b4b8 {
  strings:
    $key_b4b8 = { e0 d0 [2] 94 c8 [2] d3 ca [2] 94 db [2] da d7 [2] d6 dd [2] c1 d6 [2] da 98 [2] e7 }

  condition:
    any of them
}