rule TTP_XOR_MULT_DOSStub_0abe {
  strings:
    $key_0abe = { 5e d6 [2] 2a ce [2] 6d cc [2] 2a dd [2] 64 d1 [2] 68 db [2] 7f d0 [2] 64 9e [2] 59 }

  condition:
    any of them
}