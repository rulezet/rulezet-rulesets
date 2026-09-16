rule TTP_XOR_MULT_DOSStub_ac80 {
  strings:
    $key_ac80 = { f8 e8 [2] 8c f0 [2] cb f2 [2] 8c e3 [2] c2 ef [2] ce e5 [2] d9 ee [2] c2 a0 [2] ff }

  condition:
    any of them
}