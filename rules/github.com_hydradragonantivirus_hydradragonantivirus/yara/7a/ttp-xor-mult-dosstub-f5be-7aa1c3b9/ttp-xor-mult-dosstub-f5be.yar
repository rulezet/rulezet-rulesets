rule TTP_XOR_MULT_DOSStub_f5be {
  strings:
    $key_f5be = { a1 d6 [2] d5 ce [2] 92 cc [2] d5 dd [2] 9b d1 [2] 97 db [2] 80 d0 [2] 9b 9e [2] a6 }

  condition:
    any of them
}