rule TTP_XOR_MULT_DOSStub_f9be {
  strings:
    $key_f9be = { ad d6 [2] d9 ce [2] 9e cc [2] d9 dd [2] 97 d1 [2] 9b db [2] 8c d0 [2] 97 9e [2] aa }

  condition:
    any of them
}