rule TTP_XOR_MULT_DOSStub_b2be {
  strings:
    $key_b2be = { e6 d6 [2] 92 ce [2] d5 cc [2] 92 dd [2] dc d1 [2] d0 db [2] c7 d0 [2] dc 9e [2] e1 }

  condition:
    any of them
}