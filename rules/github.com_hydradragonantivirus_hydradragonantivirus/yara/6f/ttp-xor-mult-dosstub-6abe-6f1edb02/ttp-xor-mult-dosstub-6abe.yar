rule TTP_XOR_MULT_DOSStub_6abe {
  strings:
    $key_6abe = { 3e d6 [2] 4a ce [2] 0d cc [2] 4a dd [2] 04 d1 [2] 08 db [2] 1f d0 [2] 04 9e [2] 39 }

  condition:
    any of them
}