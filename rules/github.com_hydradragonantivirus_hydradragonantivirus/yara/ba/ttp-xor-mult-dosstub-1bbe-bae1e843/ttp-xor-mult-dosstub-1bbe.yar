rule TTP_XOR_MULT_DOSStub_1bbe {
  strings:
    $key_1bbe = { 4f d6 [2] 3b ce [2] 7c cc [2] 3b dd [2] 75 d1 [2] 79 db [2] 6e d0 [2] 75 9e [2] 48 }

  condition:
    any of them
}