rule TTP_XOR_MULT_DOSStub_45be {
  strings:
    $key_45be = { 11 d6 [2] 65 ce [2] 22 cc [2] 65 dd [2] 2b d1 [2] 27 db [2] 30 d0 [2] 2b 9e [2] 16 }

  condition:
    any of them
}