rule TTP_XOR_MULT_DOSStub_01be {
  strings:
    $key_01be = { 55 d6 [2] 21 ce [2] 66 cc [2] 21 dd [2] 6f d1 [2] 63 db [2] 74 d0 [2] 6f 9e [2] 52 }

  condition:
    any of them
}