rule TTP_XOR_MULT_DOSStub_71be {
  strings:
    $key_71be = { 25 d6 [2] 51 ce [2] 16 cc [2] 51 dd [2] 1f d1 [2] 13 db [2] 04 d0 [2] 1f 9e [2] 22 }

  condition:
    any of them
}