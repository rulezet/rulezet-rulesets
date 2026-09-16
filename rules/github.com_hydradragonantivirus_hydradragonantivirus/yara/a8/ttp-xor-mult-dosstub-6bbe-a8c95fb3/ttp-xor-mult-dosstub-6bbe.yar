rule TTP_XOR_MULT_DOSStub_6bbe {
  strings:
    $key_6bbe = { 3f d6 [2] 4b ce [2] 0c cc [2] 4b dd [2] 05 d1 [2] 09 db [2] 1e d0 [2] 05 9e [2] 38 }

  condition:
    any of them
}