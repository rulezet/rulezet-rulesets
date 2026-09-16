rule TTP_XOR_MULT_DOSStub_acd6 {
  strings:
    $key_acd6 = { f8 be [2] 8c a6 [2] cb a4 [2] 8c b5 [2] c2 b9 [2] ce b3 [2] d9 b8 [2] c2 f6 [2] ff }

  condition:
    any of them
}