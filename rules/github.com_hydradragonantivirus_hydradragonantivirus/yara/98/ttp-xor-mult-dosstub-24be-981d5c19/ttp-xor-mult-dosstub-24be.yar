rule TTP_XOR_MULT_DOSStub_24be {
  strings:
    $key_24be = { 70 d6 [2] 04 ce [2] 43 cc [2] 04 dd [2] 4a d1 [2] 46 db [2] 51 d0 [2] 4a 9e [2] 77 }

  condition:
    any of them
}