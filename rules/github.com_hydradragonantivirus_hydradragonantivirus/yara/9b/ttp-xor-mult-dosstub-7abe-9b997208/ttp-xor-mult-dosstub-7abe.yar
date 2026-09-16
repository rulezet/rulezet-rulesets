rule TTP_XOR_MULT_DOSStub_7abe {
  strings:
    $key_7abe = { 2e d6 [2] 5a ce [2] 1d cc [2] 5a dd [2] 14 d1 [2] 18 db [2] 0f d0 [2] 14 9e [2] 29 }

  condition:
    any of them
}