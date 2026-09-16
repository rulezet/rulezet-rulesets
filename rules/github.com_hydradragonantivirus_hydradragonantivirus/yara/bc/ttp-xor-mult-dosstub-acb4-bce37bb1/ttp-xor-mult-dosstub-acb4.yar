rule TTP_XOR_MULT_DOSStub_acb4 {
  strings:
    $key_acb4 = { f8 dc [2] 8c c4 [2] cb c6 [2] 8c d7 [2] c2 db [2] ce d1 [2] d9 da [2] c2 94 [2] ff }

  condition:
    any of them
}