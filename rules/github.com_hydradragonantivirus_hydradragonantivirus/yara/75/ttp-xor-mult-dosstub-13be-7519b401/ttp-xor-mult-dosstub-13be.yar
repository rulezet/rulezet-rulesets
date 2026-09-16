rule TTP_XOR_MULT_DOSStub_13be {
  strings:
    $key_13be = { 47 d6 [2] 33 ce [2] 74 cc [2] 33 dd [2] 7d d1 [2] 71 db [2] 66 d0 [2] 7d 9e [2] 40 }

  condition:
    any of them
}