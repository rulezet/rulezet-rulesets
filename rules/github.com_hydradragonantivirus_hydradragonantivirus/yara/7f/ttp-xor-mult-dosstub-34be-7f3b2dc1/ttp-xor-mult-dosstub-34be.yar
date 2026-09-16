rule TTP_XOR_MULT_DOSStub_34be {
  strings:
    $key_34be = { 60 d6 [2] 14 ce [2] 53 cc [2] 14 dd [2] 5a d1 [2] 56 db [2] 41 d0 [2] 5a 9e [2] 67 }

  condition:
    any of them
}