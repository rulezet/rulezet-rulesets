rule TTP_XOR_MULT_DOSStub_e2be {
  strings:
    $key_e2be = { b6 d6 [2] c2 ce [2] 85 cc [2] c2 dd [2] 8c d1 [2] 80 db [2] 97 d0 [2] 8c 9e [2] b1 }

  condition:
    any of them
}