rule TTP_XOR_MULT_DOSStub_26be {
  strings:
    $key_26be = { 72 d6 [2] 06 ce [2] 41 cc [2] 06 dd [2] 48 d1 [2] 44 db [2] 53 d0 [2] 48 9e [2] 75 }

  condition:
    any of them
}