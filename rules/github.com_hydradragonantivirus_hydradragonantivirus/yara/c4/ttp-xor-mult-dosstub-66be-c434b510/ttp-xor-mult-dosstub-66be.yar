rule TTP_XOR_MULT_DOSStub_66be {
  strings:
    $key_66be = { 32 d6 [2] 46 ce [2] 01 cc [2] 46 dd [2] 08 d1 [2] 04 db [2] 13 d0 [2] 08 9e [2] 35 }

  condition:
    any of them
}