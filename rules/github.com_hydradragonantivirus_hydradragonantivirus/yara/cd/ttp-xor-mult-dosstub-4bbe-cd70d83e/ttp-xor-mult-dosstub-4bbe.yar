rule TTP_XOR_MULT_DOSStub_4bbe {
  strings:
    $key_4bbe = { 1f d6 [2] 6b ce [2] 2c cc [2] 6b dd [2] 25 d1 [2] 29 db [2] 3e d0 [2] 25 9e [2] 18 }

  condition:
    any of them
}