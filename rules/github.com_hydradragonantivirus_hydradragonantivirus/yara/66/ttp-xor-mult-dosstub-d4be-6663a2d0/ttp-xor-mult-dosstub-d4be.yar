rule TTP_XOR_MULT_DOSStub_d4be {
  strings:
    $key_d4be = { 80 d6 [2] f4 ce [2] b3 cc [2] f4 dd [2] ba d1 [2] b6 db [2] a1 d0 [2] ba 9e [2] 87 }

  condition:
    any of them
}