rule TTP_XOR_MULT_DOSStub_43be {
  strings:
    $key_43be = { 17 d6 [2] 63 ce [2] 24 cc [2] 63 dd [2] 2d d1 [2] 21 db [2] 36 d0 [2] 2d 9e [2] 10 }

  condition:
    any of them
}