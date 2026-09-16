rule TTP_XOR_MULT_DOSStub_b4be {
  strings:
    $key_b4be = { e0 d6 [2] 94 ce [2] d3 cc [2] 94 dd [2] da d1 [2] d6 db [2] c1 d0 [2] da 9e [2] e7 }

  condition:
    any of them
}