rule TTP_XOR_MULT_DOSStub_ebbe {
  strings:
    $key_ebbe = { bf d6 [2] cb ce [2] 8c cc [2] cb dd [2] 85 d1 [2] 89 db [2] 9e d0 [2] 85 9e [2] b8 }

  condition:
    any of them
}