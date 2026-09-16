rule TTP_XOR_MULT_DOSStub_e0be {
  strings:
    $key_e0be = { b4 d6 [2] c0 ce [2] 87 cc [2] c0 dd [2] 8e d1 [2] 82 db [2] 95 d0 [2] 8e 9e [2] b3 }

  condition:
    any of them
}