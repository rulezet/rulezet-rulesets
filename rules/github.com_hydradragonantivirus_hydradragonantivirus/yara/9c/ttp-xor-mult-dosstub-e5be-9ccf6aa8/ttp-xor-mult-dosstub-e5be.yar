rule TTP_XOR_MULT_DOSStub_e5be {
  strings:
    $key_e5be = { b1 d6 [2] c5 ce [2] 82 cc [2] c5 dd [2] 8b d1 [2] 87 db [2] 90 d0 [2] 8b 9e [2] b6 }

  condition:
    any of them
}