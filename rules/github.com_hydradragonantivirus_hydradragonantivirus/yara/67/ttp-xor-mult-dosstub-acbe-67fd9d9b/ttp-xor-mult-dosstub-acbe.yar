rule TTP_XOR_MULT_DOSStub_acbe {
  strings:
    $key_acbe = { f8 d6 [2] 8c ce [2] cb cc [2] 8c dd [2] c2 d1 [2] ce db [2] d9 d0 [2] c2 9e [2] ff }

  condition:
    any of them
}