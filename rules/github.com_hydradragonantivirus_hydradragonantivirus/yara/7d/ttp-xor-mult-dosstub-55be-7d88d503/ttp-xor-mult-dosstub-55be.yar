rule TTP_XOR_MULT_DOSStub_55be {
  strings:
    $key_55be = { 01 d6 [2] 75 ce [2] 32 cc [2] 75 dd [2] 3b d1 [2] 37 db [2] 20 d0 [2] 3b 9e [2] 06 }

  condition:
    any of them
}