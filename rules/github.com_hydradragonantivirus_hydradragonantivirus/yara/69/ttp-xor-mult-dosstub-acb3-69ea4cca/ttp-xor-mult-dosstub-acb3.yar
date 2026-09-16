rule TTP_XOR_MULT_DOSStub_acb3 {
  strings:
    $key_acb3 = { f8 db [2] 8c c3 [2] cb c1 [2] 8c d0 [2] c2 dc [2] ce d6 [2] d9 dd [2] c2 93 [2] ff }

  condition:
    any of them
}