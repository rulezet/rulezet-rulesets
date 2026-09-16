rule TTP_XOR_MULT_DOSStub_22be {
  strings:
    $key_22be = { 76 d6 [2] 02 ce [2] 45 cc [2] 02 dd [2] 4c d1 [2] 40 db [2] 57 d0 [2] 4c 9e [2] 71 }

  condition:
    any of them
}