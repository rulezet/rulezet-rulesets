rule TTP_XOR_MULT_DOSStub_b3be {
  strings:
    $key_b3be = { e7 d6 [2] 93 ce [2] d4 cc [2] 93 dd [2] dd d1 [2] d1 db [2] c6 d0 [2] dd 9e [2] e0 }

  condition:
    any of them
}