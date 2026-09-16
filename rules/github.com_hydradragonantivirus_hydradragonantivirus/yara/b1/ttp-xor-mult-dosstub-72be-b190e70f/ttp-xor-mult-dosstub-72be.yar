rule TTP_XOR_MULT_DOSStub_72be {
  strings:
    $key_72be = { 26 d6 [2] 52 ce [2] 15 cc [2] 52 dd [2] 1c d1 [2] 10 db [2] 07 d0 [2] 1c 9e [2] 21 }

  condition:
    any of them
}