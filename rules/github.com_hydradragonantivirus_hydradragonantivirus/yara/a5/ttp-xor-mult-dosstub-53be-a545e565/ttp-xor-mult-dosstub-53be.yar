rule TTP_XOR_MULT_DOSStub_53be {
  strings:
    $key_53be = { 07 d6 [2] 73 ce [2] 34 cc [2] 73 dd [2] 3d d1 [2] 31 db [2] 26 d0 [2] 3d 9e [2] 00 }

  condition:
    any of them
}