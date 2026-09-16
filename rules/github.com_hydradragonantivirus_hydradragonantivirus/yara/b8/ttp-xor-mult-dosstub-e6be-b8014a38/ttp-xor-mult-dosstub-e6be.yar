rule TTP_XOR_MULT_DOSStub_e6be {
  strings:
    $key_e6be = { b2 d6 [2] c6 ce [2] 81 cc [2] c6 dd [2] 88 d1 [2] 84 db [2] 93 d0 [2] 88 9e [2] b5 }

  condition:
    any of them
}