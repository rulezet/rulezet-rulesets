rule TTP_XOR_MULT_DOSStub_fabe {
  strings:
    $key_fabe = { ae d6 [2] da ce [2] 9d cc [2] da dd [2] 94 d1 [2] 98 db [2] 8f d0 [2] 94 9e [2] a9 }

  condition:
    any of them
}