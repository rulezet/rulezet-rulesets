rule TTP_XOR_MULT_DOSStub_30be {
  strings:
    $key_30be = { 64 d6 [2] 10 ce [2] 57 cc [2] 10 dd [2] 5e d1 [2] 52 db [2] 45 d0 [2] 5e 9e [2] 63 }

  condition:
    any of them
}