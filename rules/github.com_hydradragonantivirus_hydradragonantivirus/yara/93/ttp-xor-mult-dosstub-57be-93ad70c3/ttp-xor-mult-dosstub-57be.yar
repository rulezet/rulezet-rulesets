rule TTP_XOR_MULT_DOSStub_57be {
  strings:
    $key_57be = { 03 d6 [2] 77 ce [2] 30 cc [2] 77 dd [2] 39 d1 [2] 35 db [2] 22 d0 [2] 39 9e [2] 04 }

  condition:
    any of them
}