rule TTP_XOR_MULT_DOSStub_e4be {
  strings:
    $key_e4be = { b0 d6 [2] c4 ce [2] 83 cc [2] c4 dd [2] 8a d1 [2] 86 db [2] 91 d0 [2] 8a 9e [2] b7 }

  condition:
    any of them
}