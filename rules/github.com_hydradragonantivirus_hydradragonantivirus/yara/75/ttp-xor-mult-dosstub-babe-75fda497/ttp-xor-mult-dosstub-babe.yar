rule TTP_XOR_MULT_DOSStub_babe {
  strings:
    $key_babe = { ee d6 [2] 9a ce [2] dd cc [2] 9a dd [2] d4 d1 [2] d8 db [2] cf d0 [2] d4 9e [2] e9 }

  condition:
    any of them
}