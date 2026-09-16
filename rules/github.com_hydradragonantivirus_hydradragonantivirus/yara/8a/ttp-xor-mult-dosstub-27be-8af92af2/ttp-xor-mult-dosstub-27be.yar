rule TTP_XOR_MULT_DOSStub_27be {
  strings:
    $key_27be = { 73 d6 [2] 07 ce [2] 40 cc [2] 07 dd [2] 49 d1 [2] 45 db [2] 52 d0 [2] 49 9e [2] 74 }

  condition:
    any of them
}